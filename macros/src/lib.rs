mod attr;

use attr::Attr;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use quote::ToTokens;
use syn::Ident;
use syn::Lit;
use syn::Token;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Data, DeriveInput, FnArg, LitStr, Pat, Type,
};

fn validator(param_name: &syn::Ident, type_ident: &syn::Ident) -> proc_macro2::TokenStream {
    match type_ident.to_string().as_str() {
        "Option" => quote! {#param_name.is_none()},
        "Vec" => quote! {#param_name.is_empty()},

        _ => todo!()
    }
}

#[proc_macro_attribute]
pub fn is_not_null(attr: TokenStream, item: TokenStream) -> TokenStream {
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


#[proc_macro_derive(ToPyDict, attributes(to_py_dict))]
pub fn to_py_dict(input: TokenStream) -> TokenStream {
    let original_struct = parse_macro_input!(input as DeriveInput);

    let name = original_struct.ident;
    let (impl_generics, ty_generics, _) = original_struct.generics.split_for_impl();

    let Data::Struct(struct_data) = original_struct.data else {
        unimplemented!("enums, Union");
    };

    let serialize_fields = struct_data.fields.iter().map(|field| {
        // field.ident is the name of the field
        let Some(ident) = &field.ident else {
            unimplemented!("tuple structs");
        };

        let parsed_field_attr = Attr::new(&field.attrs);

        let field_name = parsed_field_attr
            .rename
            .map(|i| i.to_string())
            .unwrap_or(ident.to_string());

           // ("ConnectionStates", self.connection_states.into_py(py)),
        quote!((#field_name, self.#ident.into_py(py)),)
    });

    let mapping = quote! {
        #[automatically_derived]
        impl #impl_generics IntoPy<PyObject> for #name #ty_generics {
            fn into_py(self, py: Python) -> PyObject {
                let l = PyList::new(
                    py,
                    &[
                        #( #serialize_fields )*
                    ],
                );
                let dict = PyDict::from_sequence(py, l.into()).unwrap();
                dict.into_py(py) // Py_INCREF
            }

        }
    };

    TokenStream::from(mapping)
}

#[derive(Debug)]
struct ParsedTokenEntry(String, proc_macro2::TokenStream);

struct ParsedMap {
    target: Ident,
    entries: Vec<ParsedTokenEntry>,
}

impl Parse for ParsedMap {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut entries = Vec::<ParsedTokenEntry>::new();

        if input.is_empty() {
            panic!("At least a type must be specified for an empty token mapping");
        }

        let target = input.parse::<Ident>()?;

        input.parse::<Token![,]>()?;

        while !input.is_empty() {
            let key = if let Ok(key) = input.parse::<syn::Ident>() {
                key.to_string()
            } else if let Ok(key) = input.parse::<LitStr>() {
                key.value()
            } else {
                panic!("Key must be either a string literal or an identifier!");
            };

            input.parse::<Token![=]>()?;

            let value = if let Ok(value) = input.parse::<syn::Expr>() {
                value.to_token_stream()
            } else if let Ok(value) = input.parse::<Lit>() {
                value.to_token_stream() // TODO выкинуть
            } else {
                panic!("Value must be either a literal or an identifier!");
            };

            entries.push(ParsedTokenEntry(key, value));

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(ParsedMap {
            target: target,
            entries,
        })
    }
}

#[proc_macro]
pub fn alt_impl(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ParsedMap);
    let mut vec = Vec::new();

    let target = input.target;

    for entry in input.entries {
        let val = entry.1;

        let name = Ident::new(&entry.0, Span::call_site());

        let part: proc_macro2::TokenStream = quote!(
            map(#val, #target::#name),
        );
        vec.push(part);
    }

    quote!({
        alt((
            #(#vec)*
        ))
    })
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn test_split_and_title() {
        assert_eq!(
            split_and_title(String::from("action_modifier")),
            "ActionModifier"
        );
    }
}
