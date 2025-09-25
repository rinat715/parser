use proc_macro::{self, TokenStream};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, FnArg, Pat, Type};

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

fn validator(param_name: &syn::Ident, type_ident: &syn::Ident) -> proc_macro2::TokenStream {
    match type_ident.to_string().as_str() {
        "Option" => quote! {#param_name.is_none()},
        "Vec" => quote! {#param_name.is_empty()},

        _ => panic!("dfdfdfdfd"),
    }
}

#[proc_macro_attribute]
pub fn validate_args(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    let mut validators: Vec<proc_macro2::TokenStream> = Vec::with_capacity(func.sig.inputs.len());

    for arg in func.sig.inputs.clone() {
        if let FnArg::Typed(v) = arg {
            match (*v.pat, *v.ty) {
                (Pat::Ident(a), Type::Path(b)) => {
                    let type_ = b
                        .path
                        .segments
                        .first()
                        .map(|segment| &segment.ident)
                        .unwrap();

                    validators.push(validator(&a.ident, &type_));
                }
                _ => (),
            }
        }
    }

    let fn_name = &func.sig.ident;
    let fn_block = &func.block;
    let fn_inputs = &func.sig.inputs;
    let fn_output = &func.sig.output;
    let fn_params = &func.sig.generics.params;
    let fn_attrs = &func.attrs;
    let fn_vis = &func.vis;

    let cond = syn::parse_macro_input!(attr as syn::PathSegment);

    quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name<#fn_params>(#fn_inputs) #fn_output {

            let args = vec![#(#validators),*];
            if args.iter().#cond(|v| *v) {
                return None;
            };

            #fn_block
        }
    }
    .into()
}
