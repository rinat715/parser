mod attr;

use attr::Attr;

mod code_struct;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use quote::ToTokens;
use syn::Ident;
use syn::ItemFn;
use syn::Lit;
use syn::ReturnType;
use syn::Token;
use syn::parse_quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Data, DeriveInput, FnArg, LitStr, Pat, Type,
};

fn validator(param_name: &syn::Ident, type_ident: &syn::Ident) -> proc_macro2::TokenStream {
    match type_ident.to_string().as_str() {
        "Option" => quote! {#param_name.is_none()},
        "Vec" => quote! {#param_name.is_empty()},

        _ => todo!(),
    }
}

#[proc_macro_attribute]
pub fn is_not_null(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    let mut validators: Vec<proc_macro2::TokenStream> = Vec::with_capacity(func.sig.inputs.len());

    for arg in func.sig.inputs.clone() {
        if let FnArg::Typed(v) = arg {
            if let (Pat::Ident(a), Type::Path(b)) = (*v.pat, *v.ty) {
                let type_ = b
                    .path
                    .segments
                    .first()
                    .map(|segment| &segment.ident)
                    .unwrap();

                validators.push(validator(&a.ident, type_));
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

#[deprecated(note = "Don't use this! Use `ToDict` instead.")]
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
        #[cfg(feature = "python")]
        impl #impl_generics pyo3::prelude::IntoPy<pyo3::prelude::PyObject> for #name #ty_generics {
            fn into_py(self, py: pyo3::prelude::Python) -> pyo3::prelude::PyObject {
                let l = pyo3::types::PyList::new(
                    py,
                    &[
                        #( #serialize_fields )*
                    ],
                );
                let dict = pyo3::types::PyDict::from_sequence(py, l.into()).unwrap();
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

        Ok(ParsedMap { target, entries })
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

#[proc_macro_derive(ToStr, attributes(serialize))]
pub fn to_str(input: TokenStream) -> TokenStream {
    let original_struct = parse_macro_input!(input as DeriveInput);

    code_struct::parse(&original_struct)
}

#[proc_macro_derive(ToDict, attributes(serialize))]
pub fn to_dict(input: TokenStream) -> TokenStream {
    let original_struct = parse_macro_input!(input as DeriveInput);

    code_struct::parse_for_dict(&original_struct)
}

#[proc_macro_derive(ToSerialzeMap, attributes(serialize))]
pub fn to_to_serialize_map(input: TokenStream) -> TokenStream {
    let original_struct = parse_macro_input!(input as DeriveInput);

    code_struct::parse_for_serialize_dict_entries(&original_struct)
}

// иишница 
#[proc_macro_attribute]
pub fn macro_move(attr: TokenStream, item: TokenStream) -> TokenStream {
    // 1. Аргументы атрибута: `ctx: &'a Rc<RefCell<Context>>` (через запятую, если их несколько)
    let ctx_args = parse_macro_input!(
        attr with syn::punctuated::Punctuated::<FnArg, Token![,]>::parse_terminated
    );

    // 2. Парсим саму функцию
    let mut item_fn = parse_macro_input!(item as ItemFn);

    // 3. Достаём исходный входной параметр (например, `s: &str`) — он пойдёт внутрь замыкания
    let (closure_pat, closure_ty) = item_fn
        .sig
        .inputs
        .iter()
        .find_map(|arg| match arg {
            FnArg::Typed(pat_type) => {
                Some(((*pat_type.pat).clone(), (*pat_type.ty).clone()))
            }
            _ => None,
        })
        .expect("macro_move: функция должна иметь хотя бы один типизированный параметр");

    // 4. Достаём исходный возвращаемый тип (он станет «внутренним» возвращаемым типом impl Fn)
    let return_type = match &item_fn.sig.output {
        ReturnType::Type(_, ty) => ty.clone(),
        _ => panic!("macro_move: функция должна иметь явный возвращаемый тип"),
    };

   // 5. ПЫТАЕМСЯ достать лайфтайм. Если его нет — будет None.
    let lifetime_opt = item_fn
        .sig
        .generics
        .lifetimes()
        .next()
        .map(|l| l.lifetime.clone());

    // 6. Заменяем входные параметры функции на ctx-параметры из атрибута
    item_fn.sig.inputs = ctx_args;

    // 7. Меняем возвращаемый тип в зависимости от наличия лайфтайма
    let new_return: Type = match lifetime_opt {
        Some(lifetime) => parse_quote!(impl Fn(&#lifetime str) -> #return_type),
        None => parse_quote!(impl Fn(&str) -> #return_type),
    };    
    item_fn.sig.output = ReturnType::Type(Default::default(), Box::new(new_return));

    // 8. Делаем функцию публичной
    item_fn.vis = parse_quote!(pub);

    // 9. Оборачиваем тело в `move |s: &str| { ... }`
    let body = &item_fn.block;
    item_fn.block = Box::new(parse_quote!({
        move |#closure_pat: #closure_ty| #body
    }));

    quote! { #item_fn }.into()
}
