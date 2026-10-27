use std::fmt;

use zeroize::Zeroizing;

use crate::error::Error;

// MIT: `KRB5_RESPONDER_QUESTION_PASSWORD` (include/krb5/krb5.hin:6502-6502)
/// An answer skips the prompter.
pub const QUESTION_PASSWORD: &str = "password";

// MIT: `KRB5_RESPONDER_QUESTION_OTP` (include/krb5/krb5.hin:6539-6539)
pub const QUESTION_OTP: &str = "otp";

/// Challenge and answer: wiped on drop.
struct Item {
    question: String,
    challenge: Option<Zeroizing<Vec<u8>>>,
    answer: Option<Zeroizing<String>>,
}

#[derive(Default)]
pub struct ResponderItems {
    items: Vec<Item>,
}

impl fmt::Debug for ResponderItems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.items.iter().map(|i| &i.question))
            .finish()
    }
}

/// Called before the prompter.
pub trait Responder {
    fn respond(&mut self, items: &mut ResponderItems) -> Result<(), Error>;
}

fn einval() -> Error {
    Error::Message("Invalid argument".into())
}

impl ResponderItems {
    // MIT: `k5_response_items_empty` (lib/krb5/krb/response_items.c:77-81)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    // MIT: `k5_response_items_list_questions` (lib/krb5/krb/response_items.c:83-89)
    #[must_use]
    pub fn list_questions(&self) -> Vec<&str> {
        self.items.iter().map(|i| i.question.as_str()).collect()
    }

    // MIT: `k5_response_items_get_challenge` (lib/krb5/krb/response_items.c:178-189)
    #[must_use]
    pub fn get_challenge(&self, question: &str) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|i| i.question == question)
            .and_then(|i| i.challenge.as_ref())
            .map(|c| c.as_slice())
    }

    // MIT: `k5_response_items_set_answer` (lib/krb5/krb/response_items.c:191-211)
    pub fn set_answer(&mut self, question: &str, answer: Option<&str>) -> Result<(), Error> {
        let item = self
            .items
            .iter_mut()
            .find(|i| i.question == question)
            .ok_or_else(einval)?;
        item.answer = answer.map(|a| Zeroizing::new(a.to_owned()));
        Ok(())
    }

    // MIT: `k5_response_items_ask_question` (lib/krb5/krb/response_items.c:156-176)
    pub(crate) fn ask_question(&mut self, question: &str, challenge: Option<&[u8]>) {
        let challenge = challenge.map(|c| Zeroizing::new(c.to_vec()));
        if let Some(item) = self.items.iter_mut().find(|i| i.question == question) {
            item.challenge = challenge;
        } else {
            self.items.push(Item {
                question: question.to_owned(),
                challenge,
                answer: None,
            });
        }
    }

    // MIT: `k5_response_items_get_answer` (lib/krb5/krb/response_items.c:213-224)
    pub(crate) fn get_answer(&self, question: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|i| i.question == question)
            .and_then(|i| i.answer.as_ref())
            .map(|a| a.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questions_keep_their_order_and_a_second_ask_replaces_the_challenge_in_place() {
        let mut items = ResponderItems::default();
        assert!(items.is_empty());
        items.ask_question("otp", Some(b"c1"));
        items.ask_question("pkinit", None);
        items.ask_question("otp", Some(b"c2"));
        assert_eq!(items.list_questions(), vec!["otp", "pkinit"]);
        assert_eq!(items.get_challenge("otp"), Some(&b"c2"[..]));
        assert_eq!(items.get_challenge("pkinit"), None);
        assert_eq!(items.get_challenge("nosuch"), None);
        assert!(!items.is_empty());
    }

    #[test]
    fn an_answer_needs_its_question_and_is_read_back_until_cleared() {
        let mut items = ResponderItems::default();
        let e = items.set_answer("otp", Some("x")).unwrap_err();
        assert_eq!(e.to_string(), "Invalid argument");
        items.ask_question("otp", None);
        items.set_answer("otp", Some("{}")).unwrap();
        assert_eq!(items.get_answer("otp"), Some("{}"));
        items.set_answer("otp", None).unwrap();
        assert_eq!(items.get_answer("otp"), None);
    }

    #[test]
    fn the_password_question_is_asked_with_an_empty_challenge_and_its_answer_is_read() {
        let mut items = ResponderItems::default();
        items.ask_question(QUESTION_PASSWORD, Some(b""));
        assert_eq!(items.list_questions(), vec![QUESTION_PASSWORD]);
        assert_eq!(items.get_challenge(QUESTION_PASSWORD), Some(&b""[..]));
        assert_eq!(items.get_answer(QUESTION_PASSWORD), None);
        items
            .set_answer(QUESTION_PASSWORD, Some("userpassword"))
            .unwrap();
        assert_eq!(items.get_answer(QUESTION_PASSWORD), Some("userpassword"));
    }

    #[test]
    fn debug_names_the_questions_and_nothing_else() {
        let mut items = ResponderItems::default();
        items.ask_question("otp", Some(b"challenge-text"));
        items.set_answer("otp", Some("answer-text")).unwrap();
        let shown = format!("{items:?}");
        assert_eq!(shown, r#"["otp"]"#);
    }
}
