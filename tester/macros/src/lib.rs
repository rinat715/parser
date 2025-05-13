use proc_macro2::Span;
use quote::quote;

use serde_derive::Deserialize;
use std::env;
use std::env::VarError;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use toml::Table;
use toml::Value;

#[derive(Deserialize)]
struct TestSuit {
    input: String,
    remaining: String,
    expected: Value,
}

impl TestSuit {
    fn run_and_check_remaining(&self, func: &proc_macro2::Ident) -> proc_macro2::TokenStream {
        let remaining = self.remaining.as_str();
        let input = self.input.as_str();

        quote! {
            let (remaining, result) = #func(#input).unwrap();
            assert_eq!(#remaining, remaining);
        }
    }
    fn expected(&self) -> proc_macro2::TokenStream{
        if self.expected.is_array() {
            let expected = self
            .expected
            .as_array()
            .unwrap()
            .iter()
            .map(|x| toml::to_string(x).unwrap());

            quote! {
                let mut index = 0;
                for inner in vec![#(#expected),*] {
                    println!("Run {}", index);
                    assert_eq!(
                        inner,
                        toml::to_string(&result[index]).unwrap()
                    );
                    index += 1
            }

        } 
    } else {
        let expected_str = toml::to_string(&self.expected).unwrap();
        let expected = expected_str.as_str();
        quote! {
            assert_eq!(#expected,  toml::to_string(&result).unwrap());
        }
    }
        
    }
}

fn fixture_dir() -> Result<PathBuf, VarError> {
    let path = PathBuf::new();
    let manifest = env::var("CARGO_MANIFEST_DIR")?;

    Ok(path.join(manifest).join("tests").join("fixtures"))
}

fn read_file_to_string(path: &str, buf: &mut String) {
    let mut f = File::open(path).unwrap();
    f.read_to_string(buf).unwrap();
}

#[proc_macro_attribute]
pub fn tester(
    attrs: proc_macro::TokenStream,
    func: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let func = syn::parse_macro_input!(func as syn::ItemFn);
    let expr = syn::parse_macro_input!(attrs as syn::LitStr);

    let test_file = fixture_dir().unwrap().join(expr.value());

    let mut buffer = String::new();
    read_file_to_string(test_file.to_str().unwrap(), &mut buffer);

    let mut vec = Vec::new();

    for (test_name, value) in buffer.parse::<Table>().unwrap() {
        println!("Run {}", test_name);
        let test: TestSuit = value.try_into().unwrap();

        let test_func = &func.sig.ident;
        let run_and_check_remainder = test.run_and_check_remaining(test_func);
        let expected = test.expected();

        
        let mut f = test_func.to_string();
        f.insert(0, '_');
        f.insert_str(0, test_name.as_str());
        let test_name_ident = syn::Ident::new(f.as_str(), Span::call_site());

        let test = quote! {
            #[test]
            fn #test_name_ident() {
                #run_and_check_remainder
                #expected
            }
        };
         vec.push(test);
    }

    let res_res = quote! {
        #func
        #(#vec)*
    };
    res_res.into()
}
