use macros::is_not_null;

#[is_not_null(all)]
fn test_all(a: Vec<u16>, b: Option<String>) -> Option<bool> {
    Some(true)
}

#[is_not_null(any)]
fn test_any(a: Vec<u16>, b: Vec<u16>) -> Option<bool> {
    Some(true)
}



#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_validate_args() {
        assert!(test_all(vec![1], Some(String::new())).unwrap());
        assert!(test_all(vec![], None).is_none());

        assert!(test_any(vec![1], vec![1]).unwrap());
        assert!(test_any(vec![1], vec![]).is_none())
    }

}
