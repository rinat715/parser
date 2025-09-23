use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(BuildOperatorType)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl domain::BuildOperatorType for #ident<bool> {
        fn single(&self) -> d::OperatorType {
            match self.0 {
                true => domain::OperatorType::NEQ,
                false => domain::OperatorType::EQ,
            }
        }

        fn range(&self) -> domain::OperatorType {
            match self.0 {
                true => domain::OperatorType::NotRange,
                false => domain::OperatorType::RANGE,
            }
        }
            }
        };
    output.into()
}
