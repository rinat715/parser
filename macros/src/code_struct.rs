#![allow(unused)]
use darling::{ast, util};
use darling::{
    ast::{Data, Fields},
    util::{Callable, Flag},
    Error, FromAttributes, FromDeriveInput, FromField as _, FromField, FromMeta, FromVariant,
};
use quote::quote;
use syn::{parse_quote, punctuated::Punctuated, Expr, Generics, Ident, Type, Visibility};
use syn::{Attribute, DeriveInput, GenericParam, ImplGenerics, TypeGenerics, WhereClause};

use proc_macro::TokenStream;

// https://github.com/TedDriggs/darling/blob/master/examples/serde.rs

/// The final data structure, that contains the entire parsed serde AST
#[derive(Debug)]
enum Input {
    StructUnit(StructUnit),
    StructNamed(StructNamed),
    StructTuple(StructTuple),
    Enum(Enum),
}

impl FromDeriveInput for Input {
    fn from_derive_input(input: &syn::DeriveInput) -> darling::Result<Self> {
        match &input.data {
            syn::Data::Struct(syn::DataStruct {
                fields: syn::Fields::Named(_),
                ..
            }) => StructNamed::from_derive_input(input).map(Self::StructNamed),
            syn::Data::Struct(syn::DataStruct {
                fields: syn::Fields::Unnamed(_),
                ..
            }) => StructTuple::from_derive_input(input).map(Self::StructTuple),
            syn::Data::Struct(syn::DataStruct {
                fields: syn::Fields::Unit,
                ..
            }) => StructUnit::from_derive_input(input).map(Self::StructUnit),
            syn::Data::Enum(data_enum) => Enum::from_derive_input(input).map(Self::Enum),
            syn::Data::Union(_) => Err(Error::custom("unions are not supported")),
        }
    }
}

#[derive(FromDeriveInput, Debug)]
#[darling(attributes(serialize))]
struct StructUnit {
    ident: Ident,
    vis: Visibility,
    generics: Generics,
    #[darling(flatten)]
    attr: StructNamedAttr,
}

#[derive(FromDeriveInput, Debug)]
#[darling(attributes(serialize))]
struct StructNamed {
    ident: Ident,
    vis: Visibility,
    generics: Generics,
    data: ast::Data<util::Ignored, FieldNamed>,
    #[darling(flatten)]
    attr: StructNamedAttr,
}

#[derive(FromDeriveInput, Debug)]
#[darling(attributes(serialize))]
struct StructTuple {
    ident: Ident,
    vis: Visibility,
    generics: Generics,
    data: ast::Data<util::Ignored, FieldTuple>,
    #[darling(flatten)]
    attr: StructTupleAttr,
}

#[derive(Debug)]
struct Enum {
    ident: Ident,
    vis: Visibility,
    generics: Generics,
    data: EnumVariants,
    attr: EnumAttr,
}

impl FromDeriveInput for Enum {
    fn from_derive_input(input: &syn::DeriveInput) -> darling::Result<Self> {
        Ok(Self {
            ident: input.ident.clone(),
            vis: input.vis.clone(),
            generics: input.generics.clone(),
            data: EnumVariants::try_from(&input.data)?,
            attr: EnumAttr::from_attributes(&input.attrs)?,
        })
    }
}

#[derive(Debug)]
enum Variant {
    Unit(VariantUnit),
    Named(VariantNamed),
    Tuple(VariantTuple),
}

#[derive(FromField, Debug)]
#[darling(attributes(serialize))]
struct FieldNamed {
    ident: Option<Ident>,
    vis: Visibility,
    ty: Type,
    #[darling(flatten)]
    attr: FieldAttr,
}

#[derive(FromField, Debug)]
#[darling(attributes(serialize))]
struct FieldTuple {
    vis: Visibility,
    ty: Type,
    #[darling(flatten)]
    attr: FieldAttr,
}

#[derive(FromVariant, Debug)]
#[darling(attributes(serialize))]
struct VariantUnit {
    ident: Ident,
    discriminant: Option<Expr>,
    #[darling(flatten)]
    attr: VariantAttr,
}

#[derive(FromVariant, Debug)]
#[darling(attributes(serialize))]
struct VariantTuple {
    ident: Ident,
    discriminant: Option<Expr>,
    fields: Fields<FieldTuple>,
    #[darling(flatten)]
    attr: VariantAttr,
}

#[derive(FromVariant, Debug)]
#[darling(attributes(serialize))]
struct VariantNamed {
    ident: Ident,
    discriminant: Option<Expr>,
    fields: Fields<FieldNamed>,
    #[darling(flatten)]
    attr: VariantAttr,
}

#[derive(FromMeta, Debug)]
struct StructNamedAttr {
    transparent: Flag,
    tag: Option<WordOr<String>>,
    #[darling(flatten)]
    common: ContainerAttr,
}

#[derive(FromMeta, Debug)]
struct StructTupleAttr {
    transparent: Flag,
    default: Option<DefaultValue>,
    #[darling(flatten)]
    common: ContainerAttr,
}

#[derive(FromAttributes, Debug)]
#[darling(attributes(serialize))]
struct EnumAttr {
    tag: Option<String>,
    untagged: Flag,
    content: Option<String>,
    variant_identifier: Flag,
    field_identifier: Flag,
    #[darling(flatten)]
    common: ContainerAttr,
}

/// Attributes applicable to fields
#[derive(FromMeta, Debug)]
struct FieldAttr {
    default: Option<DefaultValue>,
    flatten: Flag,
    skip_serializing_if: Option<Callable>,
    skip_deserializing_if: Option<Callable>,
    getter: Option<Callable>,
    rename: Option<Granular<String>>,
    rename_all: Option<Granular<RenameAll>>,
    skip: Flag,
    skip_none: Flag,
    skip_serializing: Flag,
    skip_deserializing: Flag,
    serialize_with: Option<Callable>,
    deserialize_with: Option<Callable>,
    with: Option<Callable>,
    #[darling(multiple)]
    alias: Vec<String>,
    borrow: Option<Borrow>,
    bound: Option<Bound>,
}

/// Attributes applicable to variants
#[derive(FromMeta, Debug)]
struct VariantAttr {
    other: Flag,
    untagged: Flag,
    rename: Option<Granular<String>>,
    rename_all: Option<Granular<RenameAll>>,
    skip: Flag,
    skip_serializing: Flag,
    skip_deserializing: Flag,
    serialize_with: Option<Callable>,
    deserialize_with: Option<Callable>,
    with: Option<Callable>,
    #[darling(multiple)]
    alias: Vec<String>,
    borrow: Option<Borrow>,
    bound: Option<Bound>,
}

/// Attributes common for both the struct and enum
#[derive(FromMeta, Debug)]
struct ContainerAttr {
    default: Option<DefaultValue>,
    rename: Option<Granular<String>>,
    rename_all: Option<Granular<RenameAll>>,
    rename_all_fields: Option<Granular<RenameAll>>,
    deny_unknown_fields: Flag,
    bound: Option<Bound>,
    remote: Option<syn::Type>,
    from: Option<syn::Type>,
    try_from: Option<syn::Type>,
    into: Option<syn::Type>,
    #[darling(rename = "crate")]
    krate: Option<syn::Path>,
    expecting: Option<String>,
}

/// #[serde(borrow)] and #[serde(borrow = "'a + 'b + ...")]
#[derive(FromMeta, Debug)]
struct Borrow(WordOr<Punctuated<syn::Lifetime, syn::Token![+]>>);

#[derive(FromMeta, Debug)]
struct Bound(Granular<syn::TypeParam>);

#[derive(FromMeta, Debug)]
struct DefaultValue(WordOr<Callable>);

#[derive(FromMeta, Debug)]
enum RenameAll {
    #[darling(rename = "lowercase")]
    Lowercase,
    #[darling(rename = "UPPERCASE")]
    Uppercase,
    #[darling(rename = "PascalCase")]
    PascalCase,
    #[darling(rename = "camelCase")]
    CamelCase,
    #[darling(rename = "snake_case")]
    SnakeCase,
    #[darling(rename = "SCREAMING_SNAKE_CASE")]
    ScreamingSnakeCase,
    #[darling(rename = "kebab-case")]
    KebabCase,
    #[darling(rename = "SCREAMING-KEBAB-CASE")]
    ScreamingKebabCase,
}

impl TryFrom<&syn::Variant> for Variant {
    type Error = darling::Error;

    fn try_from(variant: &syn::Variant) -> Result<Self, Self::Error> {
        Ok(match variant.fields {
            syn::Fields::Named(_) => Self::Named(VariantNamed::from_variant(variant)?),
            syn::Fields::Unnamed(_) => Self::Tuple(VariantTuple::from_variant(variant)?),
            syn::Fields::Unit => Self::Unit(VariantUnit::from_variant(variant)?),
        })
    }
}

/// For `default: WordOr<String>`, this allows `default` and `default = "four"`
#[derive(Debug, FromMeta)]
#[darling(from_word = || Ok(Self::Word))]
enum WordOr<T> {
    Word,
    Other(T),
}

/// For `rename: Granular<T>`, this allows `rename = "x"` and `rename(serialize = "a", deserialize = "b")`
#[derive(Debug, PartialEq, Eq)]
enum Granular<T> {
    /// Single value decides for both serialization and deserialization
    Both(T),
    /// Fine-grained control over which value is used for serialization or deserialization
    Each {
        serialize: Option<T>,
        deserialize: Option<T>,
    },
}

impl<T: FromMeta> FromMeta for Granular<T> {
    fn from_value(value: &syn::Lit) -> darling::Result<Self> {
        T::from_value(value).map(Self::Both)
    }

    fn from_list(items: &[darling::ast::NestedMeta]) -> darling::Result<Self> {
        #[derive(FromMeta, Debug, PartialEq, Eq)]
        struct GranularEach<T> {
            serialize: Option<T>,
            deserialize: Option<T>,
        }
        GranularEach::from_list(items).map(
            |GranularEach {
                 serialize,
                 deserialize,
             }| Self::Each {
                serialize,
                deserialize,
            },
        )
    }
}

#[derive(Debug)]
struct StructTupleFields {
    fields: Vec<FieldTuple>,
}

impl TryFrom<&syn::Data> for StructTupleFields {
    type Error = darling::Error;

    fn try_from(data: &syn::Data) -> Result<Self, Self::Error> {
        let mut errors = darling::Error::accumulator();
        let syn::Data::Struct(syn::DataStruct {
            fields: syn::Fields::Unnamed(fields),
            ..
        }) = data
        else {
            unreachable!()
        };
        let fields = fields
            .unnamed
            .iter()
            .filter_map(|field| errors.handle(FieldTuple::from_field(field)))
            .collect();
        errors.finish()?;

        Ok(Self { fields })
    }
}

#[derive(Debug)]
struct StructNamedFields {
    fields: Vec<FieldNamed>,
}

impl TryFrom<&syn::Data> for StructNamedFields {
    type Error = darling::Error;

    fn try_from(data: &syn::Data) -> Result<Self, Self::Error> {
        let mut errors = darling::Error::accumulator();
        let syn::Data::Struct(syn::DataStruct {
            fields: syn::Fields::Named(fields),
            ..
        }) = data
        else {
            unreachable!()
        };
        let fields = fields
            .named
            .iter()
            .filter_map(|field| errors.handle(FieldNamed::from_field(field)))
            .collect();
        errors.finish()?;

        Ok(Self { fields })
    }
}

#[derive(Debug)]
struct EnumVariants {
    variants: Vec<Variant>,
}

impl TryFrom<&syn::Data> for EnumVariants {
    type Error = darling::Error;

    fn try_from(data: &syn::Data) -> Result<Self, Self::Error> {
        let mut errors = darling::Error::accumulator();
        let syn::Data::Enum(variants) = data else {
            unreachable!()
        };
        let fields = variants
            .variants
            .iter()
            .filter_map(|field| errors.handle(Variant::try_from(field)))
            .collect();
        errors.finish()?;

        Ok(Self { variants: fields })
    }
}

fn serialize_for_str(name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        #[automatically_derived]
        #[cfg(feature = "python")]
        impl crate::domain::pythonize::ToPyString for #name {
            fn to_py_str(self, py: pyo3::prelude::Python) -> &'_ pyo3::types::PyString
            where
                Self: Sized,
                Self: crate::domain::generic::EnumToStr
                {
                    use crate::domain::generic::EnumToStr;
                    pyo3::types::PyString::new(py, self.to_str())
                }
        }

        #[automatically_derived]
        #[cfg(feature = "python")]
        impl pyo3::prelude::IntoPy<pyo3::prelude::PyObject> for #name {
            fn into_py(self, py: pyo3::prelude::Python) -> pyo3::prelude::PyObject {
                use crate::domain::pythonize::ToPyString;
                self.to_py_str(py).into_py(py)
            }
        }

        #[automatically_derived]
        impl serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                use crate::domain::generic::EnumToStr;
                serializer.serialize_str(self.to_str())
            }
        }
    }
}

pub fn parse(input: &DeriveInput) -> TokenStream {
    let original_struct = Input::from_derive_input(input).unwrap();

    match original_struct {
        Input::StructUnit(struct_unit) => todo!(),
        Input::StructNamed(struct_named) => todo!(),
        Input::StructTuple(struct_tuple) => {
            let name = struct_tuple.ident;
            let serialize = serialize_for_str(&name);
            TokenStream::from(serialize)
        }
        Input::Enum(e) => {
            let name = e.ident;

            let mut renamed_fields = Vec::new();

            e.data.variants.iter().for_each(|v| {
                if let Variant::Unit(v_inner) = v {
                    if let Some(name_enum) = &v_inner.attr.rename {
                        match name_enum {
                            Granular::Both(name) => {
                                let indent = &v_inner.ident;
                                renamed_fields.push(quote!(Self::#indent => #name,));
                            }
                            Granular::Each {
                                serialize,
                                deserialize,
                            } => todo!(),
                        }
                    }
                };
            });

            let serialize = serialize_for_str(&name);

            if renamed_fields.is_empty() {
                TokenStream::from(serialize)
            } else {
                let mapping = quote! {
                    #serialize

                    #[automatically_derived]
                    impl crate::domain::generic::EnumToStr for #name {
                        fn to_str(&self) -> &'static str {
                            match self {
                                #( #renamed_fields )*
                            }
                        }
                    }
                };

                TokenStream::from(mapping)
            }
        }
    }
}

fn add_trait_py_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(type_param) = param {
            type_param
                .bounds
                .push(parse_quote!(pyo3::prelude::IntoPy<pyo3::prelude::PyObject>));
        }
    }
    generics
}

fn add_trait_serialize_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(type_param) = param {
            type_param.bounds.push(parse_quote!(serde::Serialize));
        }
    }
    generics
}

fn serialize_for_dict(
    name: &Ident,
    generics: Generics,
    map_items: Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let generics = add_trait_serialize_bounds(generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let len = map_items.len();

    quote! {
        #[automatically_derived]
        impl #impl_generics serde::Serialize for #name #ty_generics #where_clause {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                use serde::ser::SerializeMap;

                let mut map = serializer.serialize_map(Some(#len))?;
                #( #map_items )*
                map.end()
            }
        }
    }
}

fn serialize_py_for_dict(
    name: &Ident,
    generics: Generics,
    tuples: Vec<proc_macro2::TokenStream>,
    try_insert: Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let generics = add_trait_py_bounds(generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        #[automatically_derived]
        #[cfg(feature = "python")]
        impl #impl_generics pyo3::prelude::IntoPy<pyo3::prelude::PyObject> for #name #ty_generics {
            fn into_py(self, py: pyo3::prelude::Python) -> pyo3::prelude::PyObject {
                use pyo3::types::IntoPyDict;
                self.into_py_dict(py).into_py(py)
            }
        }

        #[automatically_derived]
        #[cfg(feature = "python")]
        impl #impl_generics pyo3::types::IntoPyDict for #name #ty_generics #where_clause {
            fn into_py_dict(self, py: pyo3::prelude::Python<'_>) -> &'_ pyo3::types::PyDict {
                use pyo3::types::IntoPyDict;

                let l = pyo3::types::PyList::new(
                    py,
                    &[
                        #( #tuples )*
                    ],
                );

                let dict = pyo3::types::PyDict::from_sequence(py, l.into()).unwrap_or(pyo3::types::PyDict::new(py));

                #( #try_insert )*

                dict
            }
        }
    }
}

fn make_item(field: &FieldNamed) -> Option<(&Ident, &str)> {
    if let Some(name_enum) = &field.attr.rename {
        if let (Some(indent), Granular::Both(name)) = (&field.ident, name_enum) {
            return Some((indent, name));
        };
    };
    None
}

fn serialize_transparent(name: &Ident, generics: Generics) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        #[automatically_derived]
        #[cfg(feature = "python")]
        impl #impl_generics pyo3::prelude::IntoPy<pyo3::prelude::PyObject> for #name #ty_generics {
            fn into_py(self, py: pyo3::prelude::Python) -> pyo3::prelude::PyObject {
                self.0.into_py(py)
            }
        }

         #[automatically_derived]
        impl #impl_generics serde::Serialize for #name #ty_generics #where_clause {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

    }
}

fn serialize_for_serialize_dict_entries(
    name: &Ident,
    generics: Generics,
    map_items: Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let generics = add_trait_serialize_bounds(generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        #[automatically_derived]
        impl #impl_generics crate::domain::serialize::SerializeDict for #name #ty_generics #where_clause {
            fn serialize_dict_entries<S>(&self, mut map: S) -> Result<S, S::Error>
            where
                S: serde::ser::SerializeMap,
            {
                #( #map_items )*
                Ok(map)
            }
        }
    }
}

pub fn parse_for_dict(input: &DeriveInput) -> TokenStream {
    let original_struct = Input::from_derive_input(input).unwrap();

    match original_struct {
        Input::StructUnit(struct_unit) => todo!(),
        Input::StructNamed(struct_named) => {
            let name = struct_named.ident;

            let mut tuples = Vec::new();
            let mut try_insert = Vec::new();
            let mut map_items = Vec::new();

            if let ast::Data::Struct(fields) = struct_named.data {
                fields.iter().for_each(|v| {
                    if let Some((indent, name)) = make_item(v) {
                        if v.attr.skip_none.is_present() {
                            try_insert.push(
                                quote!(crate::domain::pythonize::try_insert(py, dict, #name, self.#indent);),
                            );
                        } else {
                            tuples.push(
                                quote!(crate::domain::pythonize::tuple(py, #name, self.#indent),),
                            );
                        }

                        let serialize = if v.attr.skip_none.is_present() {
                            quote! {
                                if self.#indent.is_some() {
                                    map.serialize_entry(#name, &self.#indent)?
                                }
                            }
                        } else {
                            quote!(map.serialize_entry(#name, &self.#indent)?;)
                        };

                        map_items.push(serialize);
                    }
                });
            };

            let serialize_py =
                serialize_py_for_dict(&name, struct_named.generics.clone(), tuples, try_insert);
            let serialize = serialize_for_dict(&name, struct_named.generics.clone(), map_items);

            let mapping = quote! {
                #serialize_py
                #serialize
            };

            TokenStream::from(mapping)
        }
        Input::StructTuple(struct_tuple) => {
            let name = struct_tuple.ident;

            if struct_tuple.attr.transparent.is_present() {
                let mapping = serialize_transparent(&name, struct_tuple.generics);
                TokenStream::from(mapping)
            } else {
                todo!("dfdf")
            }
        }
        Input::Enum(_) => todo!(),
    }
}

pub fn parse_for_serialize_dict_entries(input: &DeriveInput) -> TokenStream {
    let original_struct = Input::from_derive_input(input).unwrap();

    match original_struct {
        Input::StructUnit(struct_unit) => todo!(),
        Input::StructNamed(struct_named) => {
            let name = struct_named.ident;

            let mut map_items = Vec::new();    

            if let ast::Data::Struct(fields) = struct_named.data {
                fields.iter().for_each(|v| {
                    if let Some((indent, name)) = make_item(v) {
                        let serialize = if v.attr.skip_none.is_present() {
                            quote! {
                                if self.#indent.is_some() {
                                    map.serialize_entry(#name, &self.#indent)?
                                }
                            }
                        } else {
                            quote!(map.serialize_entry(#name, &self.#indent)?;)
                        };

                        map_items.push(serialize);
                    }
                });
            };

            let serialize = serialize_for_serialize_dict_entries(
                &name,
                struct_named.generics.clone(),
                map_items,
            );

            TokenStream::from(serialize)
        }
        Input::StructTuple(struct_tuple) => todo!(),
        Input::Enum(_) => todo!(),
    }
}

