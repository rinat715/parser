use proc_macro2::Span;
use quote::quote;

use serde_derive::Deserialize;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use toml::Table;
use toml::Value;

type Error = syn::Error;
type Result<T> = syn::Result<T>;

#[derive(Deserialize)]
struct TestSuit {
    input: String,
    remaining: String,
    expected: Value,
}

impl TestSuit {
    fn run(&self, func: &proc_macro2::Ident) -> proc_macro2::TokenStream {
        let input = self.input.as_str();

        quote! {
            let (remaining, result) = #func(#input).unwrap();
        }
    }
    fn remainder(&self) -> proc_macro2::TokenStream {
        let remaining = self.remaining.as_str();

        quote! {
            assert_eq!(#remaining, remaining, "wrong remaining {} {}", #remaining, remaining);
        }
    }
    fn expected(&self) -> proc_macro2::TokenStream {
        if self.expected.is_array() {
            let expected = self
                .expected
                .as_array()
                .unwrap()
                .iter()
                .map(|x| toml::to_string(x).unwrap()); // TODO обрабтывать ошибку

            quote! {
                    let mut index = 0;
                    for inner in vec![#(#expected),*] {
                        println!("Run {}", index);
                        assert_eq!(
                            inner,
                            toml::to_string(&result[index]).unwrap(),
                            "wrong expected {} {}", inner, toml::to_string(&result[index]).unwrap()
                        );
                        index += 1
                }

            }
        } else {

            if self.expected.is_str()
             {
                let expected = self.expected.as_str(); // TODO обрабтывать ошибку
                quote! {
                    assert_eq!(#expected,  result, "wrong expected {} {}", #expected, result);
                }

            } else {
                let expected_str = toml::to_string(&self.expected).unwrap(); // TODO обрабтывать ошибку
                let expected = expected_str.as_str();
                quote! {
                    assert_eq!(#expected,  toml::to_string(&result).unwrap(), "wrong expected {} {}", #expected, toml::to_string(&result).unwrap());
                }
            }


        }
    }
    fn name(&self, func: &str, name: &str) -> syn::Ident {
        let mut s = name.to_owned();
        s.insert(0, '_');
        s.insert_str(0, func);
        syn::Ident::new(s.as_str(), Span::call_site())
    }

    fn build_test(&self, func: &proc_macro2::Ident, name: &str) -> proc_macro2::TokenStream {
        let expected = self.expected();
        let run = self.run(func);
        let remainder = self.remainder();
        let name = self.name(func.to_string().as_str(), name);

        quote! {
            #[test]
            fn #name() {
                #run
                #remainder
                #expected
            }
        }
    }
}

struct TestFile();

impl TestFile {
    fn new() -> Self {
        Self {}
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        let manifest = env::var("CARGO_MANIFEST_DIR").map_err(|e| {
            Error::new_spanned(
                "CARGO_MANIFEST_DIR",
                format!("failed to resolve env var CARGO_MANIFEST_DIR: {e}"),
            )
        })?;

        let path = PathBuf::new();
        let file = path
            .join(manifest)
            .join("tests")
            .join("fixtures")
            .join(name);

        Ok(file)
    }

    fn open(&self, path: PathBuf, buf: &mut String) -> Result<()> {
        let mut f = File::open(path)
            .map_err(|e| Error::new_spanned("ddfdfdf", format!("fail to open file: {e}")))?;

        f.read_to_string(buf).map_err(|e| {
            Error::new_spanned("CARGO_MANIFEST_DIR", format!("fail to read file: {e}"))
        })?;

        Ok(())
    }

    fn read(&self, name: &str) -> Result<String> {
        let path = self.path(name)?;
        let mut content = String::new();
        let buf = &mut content;
        self.open(path, buf)?;
        Ok(content)
    }
}

#[proc_macro_attribute]
pub fn tester(
    attrs: proc_macro::TokenStream,
    func: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let func = syn::parse_macro_input!(func as syn::ItemFn);
    let expr = syn::parse_macro_input!(attrs as syn::LitStr);

    let file = TestFile::new().read(expr.value().as_str()).unwrap();

    let mut vec = Vec::new();

    for (test_name, value) in file.parse::<Table>().unwrap() {
        println!("Run {}", test_name);

        let test: TestSuit = value.try_into().unwrap();
        vec.push(test.build_test(&func.sig.ident, test_name.as_str()));
    }

    let res_res = quote! {
        #func
        #(#vec)*
    };
    res_res.into()
}
