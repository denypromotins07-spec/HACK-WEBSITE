//! GraphQL Schema Map Module
//! Builds a zero-copy in-memory schema map for subsequent mutation and query tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct GraphQLEnumValue {
    pub name: String,
    pub description: Option<String>,
    pub is_deprecated: bool,
}

#[derive(Debug, Clone)]
pub struct GraphQLField {
    pub name: String,
    pub description: Option<String>,
    pub field_type: GraphQLTypeRef,
    pub args: Vec<GraphQLArg>,
    pub is_deprecated: bool,
}

#[derive(Debug, Clone)]
pub struct GraphQLArg {
    pub name: String,
    pub arg_type: GraphQLTypeRef,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GraphQLInputField {
    pub name: String,
    pub field_type: GraphQLTypeRef,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone)]
pub enum GraphQLTypeRef {
    Scalar(String),
    Object(String),
    Interface(String),
    Union(String),
    Enum(String),
    InputObject(String),
    List(Box<GraphQLTypeRef>),
    NonNull(Box<GraphQLTypeRef>),
}

impl GraphQLTypeRef {
    pub fn base_type_name(&self) -> &str {
        match self {
            GraphQLTypeRef::Scalar(name) => name,
            GraphQLTypeRef::Object(name) => name,
            GraphQLTypeRef::Interface(name) => name,
            GraphQLTypeRef::Union(name) => name,
            GraphQLTypeRef::Enum(name) => name,
            GraphQLTypeRef::InputObject(name) => name,
            GraphQLTypeRef::List(inner) => inner.base_type_name(),
            GraphQLTypeRef::NonNull(inner) => inner.base_type_name(),
        }
    }

    pub fn is_list(&self) -> bool {
        matches!(self, GraphQLTypeRef::List(_))
    }

    pub fn is_non_null(&self) -> bool {
        matches!(self, GraphQLTypeRef::NonNull(_))
    }
}

#[derive(Debug, Clone)]
pub struct GraphQLType {
    pub kind: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub fields: Option<Vec<GraphQLField>>,
    pub input_fields: Option<Vec<GraphQLInputField>>,
    pub interfaces: Vec<String>,
    pub enum_values: Option<Vec<GraphQLEnumValue>>,
    pub possible_types: Option<Vec<String>>,
}

#[derive(Default)]
pub struct SchemaMap {
    pub types: BTreeMap<String, GraphQLType>,
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
    pub directives: Vec<GraphQLDirective>,
    type_cache: HashMap<u64, Arc<GraphQLType>>,
}

#[derive(Debug, Clone)]
pub struct GraphQLDirective {
    pub name: String,
    pub description: Option<String>,
    pub locations: Vec<String>,
    pub args: Vec<GraphQLArg>,
}

impl SchemaMap {
    pub fn new() -> Self {
        Self {
            types: BTreeMap::new(),
            query_type: None,
            mutation_type: None,
            subscription_type: None,
            directives: Vec::new(),
            type_cache: HashMap::new(),
        }
    }

    pub fn from_introspection(schema_json: &serde_json::Value) -> Option<Self> {
        let schema = schema_json.get("__schema")?;
        let mut map = SchemaMap::new();

        if let Some(query_type) = schema.get("queryType").and_then(|q| q.get("name")).and_then(|n| n.as_str()) {
            map.query_type = Some(query_type.to_string());
        }

        if let Some(mutation_type) = schema.get("mutationType").and_then(|m| m.get("name")).and_then(|n| n.as_str()) {
            map.mutation_type = Some(mutation_type.to_string());
        }

        if let Some(subscription_type) = schema.get("subscriptionType").and_then(|s| s.get("name")).and_then(|n| n.as_str()) {
            map.subscription_type = Some(subscription_type.to_string());
        }

        if let Some(types) = schema.get("types").and_then(|t| t.as_array()) {
            for t in types {
                if let Some(type_obj) = Self::parse_type(t) {
                    if let Some(name) = type_obj.name.clone() {
                        if !name.starts_with("__") || name == "__Schema" || name == "__Type" {
                            map.types.insert(name, type_obj);
                        }
                    }
                }
            }
        }

        if let Some(directives) = schema.get("directives").and_then(|d| d.as_array()) {
            for d in directives {
                if let Some(dir) = Self::parse_directive(d) {
                    map.directives.push(dir);
                }
            }
        }

        Some(map)
    }

    fn parse_type(value: &serde_json::Value) -> Option<GraphQLType> {
        let kind = value.get("kind")?.as_str()?.to_string();
        let name = value.get("name").and_then(|n| n.as_str()).map(String::from);
        let description = value.get("description").and_then(|d| d.as_str()).map(String::from);

        let fields = value.get("fields")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        let name = f.get("name")?.as_str()?.to_string();
                        let desc = f.get("description").and_then(|d| d.as_str()).map(String::from);
                        let field_type = Self::parse_type_ref(f.get("type")?)?;
                        let args = f.get("args")
                            .and_then(|a| a.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|a| {
                                        let name = a.get("name")?.as_str()?.to_string();
                                        let arg_type = Self::parse_type_ref(a.get("type")?)?;
                                        let default = a.get("defaultValue").and_then(|d| d.as_str()).map(String::from);
                                        Some(GraphQLArg { name, arg_type, default_value: default })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let is_deprecated = f.get("isDeprecated").and_then(|b| b.as_bool()).unwrap_or(false);
                        Some(GraphQLField { name, description: desc, field_type, args, is_deprecated })
                    })
                    .collect()
            });

        let input_fields = value.get("inputFields")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        let name = f.get("name")?.as_str()?.to_string();
                        let field_type = Self::parse_type_ref(f.get("type")?)?;
                        let default = f.get("defaultValue").and_then(|d| d.as_str()).map(String::from);
                        Some(GraphQLInputField { name, field_type, default_value: default })
                    })
                    .collect()
            });

        let interfaces = value.get("interfaces")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|i| i.get("name")?.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let enum_values = value.get("enumValues")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let name = e.get("name")?.as_str()?.to_string();
                        let desc = e.get("description").and_then(|d| d.as_str()).map(String::from);
                        let is_deprecated = e.get("isDeprecated").and_then(|b| b.as_bool()).unwrap_or(false);
                        Some(GraphQLEnumValue { name, description: desc, is_deprecated })
                    })
                    .collect()
            });

        let possible_types = value.get("possibleTypes")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p.get("name")?.as_str().map(String::from))
                    .collect()
            });

        Some(GraphQLType {
            kind,
            name,
            description,
            fields,
            input_fields,
            interfaces,
            enum_values,
            possible_types,
        })
    }

    fn parse_type_ref(value: &serde_json::Value) -> Option<GraphQLTypeRef> {
        let kind = value.get("kind")?.as_str()?;
        let name = value.get("name").and_then(|n| n.as_str());

        match kind {
            "SCALAR" => Some(GraphQLTypeRef::Scalar(name?.to_string())),
            "OBJECT" => Some(GraphQLTypeRef::Object(name?.to_string())),
            "INTERFACE" => Some(GraphQLTypeRef::Interface(name?.to_string())),
            "UNION" => Some(GraphQLTypeRef::Union(name?.to_string())),
            "ENUM" => Some(GraphQLTypeRef::Enum(name?.to_string())),
            "INPUT_OBJECT" => Some(GraphQLTypeRef::InputObject(name?.to_string())),
            "LIST" => {
                let inner = Self::parse_type_ref(value.get("ofType")?)?;
                Some(GraphQLTypeRef::List(Box::new(inner)))
            }
            "NON_NULL" => {
                let inner = Self::parse_type_ref(value.get("ofType")?)?;
                Some(GraphQLTypeRef::NonNull(Box::new(inner)))
            }
            _ => None,
        }
    }

    fn parse_directive(value: &serde_json::Value) -> Option<GraphQLDirective> {
        let name = value.get("name")?.as_str()?.to_string();
        let description = value.get("description").and_then(|d| d.as_str()).map(String::from);
        
        let locations = value.get("locations")
            .and_then(|l| l.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|l| l.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let args = value.get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        let name = a.get("name")?.as_str()?.to_string();
                        let arg_type = Self::parse_type_ref(a.get("type")?)?;
                        let default = a.get("defaultValue").and_then(|d| d.as_str()).map(String::from);
                        Some(GraphQLArg { name, arg_type, default_value: default })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(GraphQLDirective { name, description, locations, args })
    }

    pub fn get_type(&self, name: &str) -> Option<&GraphQLType> {
        self.types.get(name)
    }

    pub fn get_cached_type(&mut self, name: &str) -> Option<Arc<GraphQLType>> {
        let hash = fxhash::hash64(name);
        if let Some(cached) = self.type_cache.get(&hash) {
            return Some(Arc::clone(cached));
        }
        
        if let Some(typ) = self.types.get(name) {
            let arc = Arc::new(typ.clone());
            self.type_cache.insert(hash, Arc::clone(&arc));
            Some(arc)
        } else {
            None
        }
    }

    pub fn get_query_fields(&self) -> Option<&Vec<GraphQLField>> {
        if let Some(query_name) = &self.query_type {
            self.types.get(query_name).and_then(|t| t.fields.as_ref())
        } else {
            None
        }
    }

    pub fn get_mutation_fields(&self) -> Option<&Vec<GraphQLField>> {
        if let Some(mutation_name) = &self.mutation_type {
            self.types.get(mutation_name).and_then(|t| t.fields.as_ref())
        } else {
            None
        }
    }

    pub fn all_input_types(&self) -> Vec<&GraphQLType> {
        self.types.values()
            .filter(|t| t.kind == "INPUT_OBJECT")
            .collect()
    }

    pub fn all_scalar_types(&self) -> Vec<&str> {
        self.types.values()
            .filter(|t| t.kind == "SCALAR")
            .filter_map(|t| t.name.as_deref())
            .collect()
    }
}

impl Default for SchemaMap {
    fn default() -> Self {
        Self::new()
    }
}
