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

// TODO наверно выкинуть макрос и сделать как https://github.com/joelself/tomllib/tree/master/assets

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
    fn remainder(&self, file_name: &str, name: &str) -> proc_macro2::TokenStream {
        let remaining = self.remaining.as_str();

        quote! {
            // TODO возможно тут лучше взять https://github.com/rust-pretty-assertions/rust-pretty-assertions/tree/main
            assert_eq!(#remaining, remaining, "{}",  diff::Diff::new(#file_name, #name, remaining, #remaining));
        }
    }
    fn expected(&self, file_name: &str, name: &str) -> proc_macro2::TokenStream {
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

                        println!("Run {}", index); // TODO не Run a Build
                        let actual = toml::to_string(&result[index]).unwrap();

                        assert_eq!(
                            inner,
                            actual,
                            "{}", diff::Diff::new(#file_name, #name, actual.as_str(), inner)
                        );
                        index += 1
                }

            }
        } else if self.expected.is_str() {
            let expected = self.expected.as_str(); // TODO обрабтывать ошибку
            quote! {
                assert_eq!(#expected,  result,  "{}", diff::Diff::new(#file_name, #name, result, #expected));
            }
        } else {
            let expected_str = toml::to_string(&self.expected).unwrap(); // TODO обрабтывать ошибку
            let expected = expected_str.as_str();
            quote! {
                let actual = toml::to_string(&result).unwrap();
                assert_eq!(#expected,  toml::to_string(&result).unwrap(), "{}", diff::Diff::new(#file_name, #name, actual.as_str(), #expected));
            }
        }
    }
    fn name(&self, func: &str, name: &str) -> syn::Ident {
        let mut s = name.to_owned();
        s.insert(0, '_');
        s.insert_str(0, func);
        syn::Ident::new(s.as_str(), Span::call_site())
    }

    fn build_test(
        &self,
        func: &proc_macro2::Ident,
        name: &str,
        file_name: &str,
    ) -> proc_macro2::TokenStream {
        let expected = self.expected(file_name, name);
        let run = self.run(func);
        let remainder = self.remainder(file_name, name);
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

struct TestFile {
    path: PathBuf,
}

impl TestFile {
    fn new() -> Self {
        Self {
            path: PathBuf::new(),
        }
    }

    fn init(&mut self) -> &mut Self {
        let manifest = env::var("CARGO_MANIFEST_DIR")
            .map_err(|e| {
                Error::new_spanned(
                    "CARGO_MANIFEST_DIR",
                    format!("failed to resolve env var CARGO_MANIFEST_DIR: {e}"),
                )
            })
            .unwrap();
        self.path = self.path.join(manifest).join("tests").join("fixtures");
        self
    }

    fn path(&mut self, name: &str) -> &mut Self {
        self.path = self.path.join(name);
        self
    }

    fn open(&self, buf: &mut String) -> Result<()> {
        let mut f = File::open(&self.path)
            .map_err(|e| Error::new_spanned("ddfdfdf", format!("fail to open file: {e}")))?;

        f.read_to_string(buf).map_err(|e| {
            Error::new_spanned("CARGO_MANIFEST_DIR", format!("fail to read file: {e}"))
        })?;

        Ok(())
    }

    fn read(&self) -> Result<String> {
        let mut content = String::new();
        let buf = &mut content;
        self.open(buf)?;
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

    let mut test_dir = TestFile::new();
    test_dir.init().path(expr.value().as_str());

    let file = test_dir.read().unwrap();
    let file_path = test_dir.path.to_string_lossy();

    let mut vec = Vec::new();

    for (test_name, value) in file.parse::<Table>().unwrap() {
        println!("Run {}", test_name);

        let test: TestSuit = value.try_into().unwrap();
        vec.push(test.build_test(&func.sig.ident, test_name.as_str(), &file_path));
    }

    let res_res = quote! {
        #func
        #(#vec)*
    };
    res_res.into()
}
