use syn::punctuated::Punctuated;
use syn::Meta;
use syn::{Result, Token};

pub struct ParsedTokenEntry(pub String, pub syn::Path);

#[derive(Default)]
pub struct Attr {
    pub target: Option<syn::Ident>,
    pub is_skip: bool,
    pub extend_fields: Vec<ParsedTokenEntry>,
    pub rename: Option<syn::Ident>,
}

impl Attr {
    pub fn new(attribs: &[syn::Attribute]) -> Self {
        let filtred: Vec<&syn::Attribute> = attribs
            .iter()
            .filter(|p| p.path().is_ident("mapping"))
            .collect();

        if filtred.is_empty() {
            return Self::default();
        }
        
        let target = Self::target(&filtred);
        let is_skip = Self::is_skip(&filtred);
        let extend_fields = Self::extend_fields(&filtred).unwrap_or_default();
        let rename = extend_fields
            .first()
            .and_then(|v| v.1.clone().get_ident().and_then(|v| Some(v.clone()))); // TODO валидировать rename

        Self {
            target,
            is_skip,
            extend_fields,
            rename,
        }
    }

    fn target(attribs: &[&syn::Attribute]) -> Option<syn::Ident> {
        let mut result = None;
        let _ = attribs.first().unwrap().parse_nested_meta(|meta| {
            if meta.input.peek(Token![=]) {
                ()
            } else {
                result = Some(meta.path.require_ident()?.clone());
            }
            Ok(())
        });

        result
    }

    fn is_skip(attribs: &[&syn::Attribute]) -> bool {
        attribs.first().map_or_else(
            || false,
            |first| {
                let mut result = false;
                let _ = first.parse_nested_meta(|meta| {
                    result = meta
                        .path
                        .get_ident()
                        .and_then(|ident| Some(ident.to_string() == "skip"))
                        .unwrap_or(false);
                    Ok(())
                });

                result
            },
        )
    }

    fn extend_fields(attribs: &[&syn::Attribute]) -> Result<Vec<ParsedTokenEntry>> {
        let mut result: Vec<ParsedTokenEntry> = Vec::new();

        for item in attribs {
            let nested = item.parse_args_with(Punctuated::<Meta, Token![=]>::parse_terminated)?;

            for attr_inner in nested {
                match attr_inner {
                    Meta::NameValue(v) => match v.value {
                        syn::Expr::Path(inner) => {
                            result.push(ParsedTokenEntry(
                                v.path.require_ident()?.to_string(),
                                inner.path,
                            ));
                        }
                        _ => (),
                    },
                    _ => (), // TODO
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_parse_attr2() {
        let attr: Vec<syn::Attribute> = parse_quote! {
            #[mapping(Token)]
            #[mapping(ActionModifier=action_modifier)]
        };

        let parsed_attrs = Attr::new(&attr);

        assert_eq!(parsed_attrs.target.unwrap().to_string(), "Token");

        let entre = parsed_attrs.extend_fields.first().unwrap();

        assert_eq!(entre.0, "ActionModifier");
        assert_eq!(
            entre.1.require_ident().unwrap().to_string(),
            "action_modifier"
        );
    }

    #[test]
    fn test_parse_token_error() {
        let attr: Vec<syn::Attribute> = parse_quote! {
            #[mapping(ActionModifier=action_modifier)]
        };

        let parsed_attrs = Attr::new(&attr);

        assert!(parsed_attrs.target.is_none());
    }

    #[test]
    fn test_parse_attr3() {
        let attr: Vec<syn::Attribute> = parse_quote! {
            #[mapping(skip)]
            #[mapping(rename = TCPFlags)]
        };

        let parsed_attrs = Attr::new(&attr);

        assert!(parsed_attrs.is_skip);

        let entre = parsed_attrs.extend_fields.first().unwrap();

        assert_eq!(entre.0, "rename");
        assert_eq!(entre.1.require_ident().unwrap().to_string(), "TCPFlags");
    }



    #[test]
    fn test_parse_skip2() {
        let attr: Vec<syn::Attribute> = parse_quote! {
            #[mapping(rename = TCPFlags)]
        };

        let parsed_attrs = Attr::new(&attr);
        assert!(!parsed_attrs.is_skip)
    }
}
