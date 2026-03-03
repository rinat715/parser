use std::str::Chars;

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

#[proc_macro_derive(BuildOperatorType)]
pub fn derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
    impl domain::BuildOperatorType for #ident<bool> {
    fn single(&self) -> d::OperatorType {
        match self.0 {
            true => domain::OperatorType::NEQ,  // TODO сделать когда true  EQ
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

        _ => panic!("dfdfdfdfd"), // TODO
    }
}

#[proc_macro_attribute]
pub fn in_not_null(attr: TokenStream, item: TokenStream) -> TokenStream {
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

fn title(mut s: Chars<'_>, cap: usize) -> String {
    let mut result = String::with_capacity(cap);
    result.push(
        s.next()
            .and_then(|c| Some(c.to_ascii_uppercase()))
            .unwrap_or_default(),
    );
    result.extend(s);
    result
}

fn split_and_title(s: String) -> String {
    s.split('_').map(|p| title(p.chars(), p.len())).collect()
}

fn target_field(s: String) -> Ident {
    Ident::new(&split_and_title(s), Span::call_site())
}

//
// https://github.com/wojciech-graj/bin-proto
#[proc_macro_derive(Mapping, attributes(mapping))]
pub fn mapping(input: TokenStream) -> TokenStream {
    let original_struct = parse_macro_input!(input as DeriveInput);

    let parsed_attrs = Attr::new(&original_struct.attrs);

    let name = original_struct.ident;
    let (impl_generics, ty_generics, _) = original_struct.generics.split_for_impl();

    let Data::Struct(struct_data) = original_struct.data else {
        unimplemented!("enums, Union");
    };

    let serialize_fields = struct_data
        .fields
        .iter()
        .map(|field| {
            // field.ident is the name of the field
            let Some(ident) = &field.ident else {
                unimplemented!("tuple structs");
            };

            let parsed_field_attr = Attr::new(&field.attrs);

            let ty = &field.ty;

            let target_field = parsed_field_attr
                .rename
                .unwrap_or(target_field(ident.to_string()));

            if parsed_field_attr.is_skip {
                quote!()
            } else {
                match ty {
                    Type::Path(tp) => {
                        let segments = &tp.path.segments;
                        if segments[0].ident == "Vec" {
                            quote!(#target_field(v) => self.#ident = v,)
                        } else if segments[0].ident == "Option" {
                            quote!(#target_field(v) => self.#ident = Some(v),)
                        } else {
                            quote!()
                        }
                    }
                    _ => panic!(),
                }
            }
        })
        .filter(|v| !v.is_empty());

    let mut vec = Vec::new();

    for entry in parsed_attrs.extend_fields {
        let val = entry.1;

        let name = Ident::new(&entry.0, Span::call_site());

        vec.push(quote!(#name(v) => self.#val(v),));
    }

    let target = parsed_attrs
        .target
        .ok_or(syn::Error::new_spanned("Target", "target requered"))
        .unwrap();

    let mapping = quote! {
        #[automatically_derived]
        impl #impl_generics Mapping<#target #impl_generics> for #name #ty_generics {
            fn mapping(&mut self, target: #target #ty_generics) {
                match target {
                    #( #target::#serialize_fields )*
                    #( #target::#vec )*
                    _ => ()
                }
            }

        }
    };

    TokenStream::from(mapping)
}

//
// https://github.com/wojciech-graj/bin-proto
#[proc_macro_derive(ToPyDict, attributes(to_py_dict))]
pub fn to_py_dict(input: TokenStream) -> TokenStream {
    let original_struct = parse_macro_input!(input as DeriveInput);

    let name = original_struct.ident;
    let (impl_generics, ty_generics, _) = original_struct.generics.split_for_impl();

    let Data::Struct(struct_data) = original_struct.data else {
        unimplemented!("enums, Union");
    };

     let serialize_fields = struct_data
        .fields
        .iter()
        .map(|field| {
            // field.ident is the name of the field
            let Some(ident) = &field.ident else {
                unimplemented!("tuple structs");
            };

            let parsed_field_attr = Attr::new(&field.attrs);

            let field_name = parsed_field_attr.rename.map(|i| i.to_string()).unwrap_or(ident.to_string());

            let message =  format!("Struct {} Failed to set key {} on dict", field_name, name.to_string());

            quote!(dict.set_item(#field_name.into_py(py), self.#ident.into_py(py)).expect(#message);)

        });

    let mapping = quote! {
        #[automatically_derived]
        impl #impl_generics IntoPy<PyObject> for #name #ty_generics {
            fn into_py(self, py: Python) -> PyObject {
                let dict = PyDict::new(py);
                #( #serialize_fields )*
                dict.into_py(py)
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
