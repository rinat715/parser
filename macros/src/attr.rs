use syn::punctuated::Punctuated;
use syn::Meta;
use syn::{Result, Token};

pub struct ParsedTokenEntry(pub syn::Path);

#[derive(Default)]
pub struct Attr {
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
        
        let extend_fields = Self::extend_fields(&filtred).unwrap_or_default();
        let rename = extend_fields
            .first()
            .and_then(|v| v.0.clone().get_ident().and_then(|v| Some(v.clone()))); // TODO валидировать rename

        Self {
            rename,
        }
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

