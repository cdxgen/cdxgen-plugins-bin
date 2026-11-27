// Impl shapes the context resolution must keep apart or keep reachable:
// same-named types in two modules, an impl that relies on the trait's
// default argument, a method's own generic parameter on a trait object, a
// trait written with a path, a lifetime argument, and a generic self type.
use context_impl_tojson as tj;
use context_impl_tojson::{Client, ToJson};
use fakeuuid::Uuid;

use crate::ApiCtx;

pub mod a {
    pub struct Err;

    impl core::fmt::Display for Err {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a")
        }
    }
}

pub mod b {
    pub struct Err;

    impl core::fmt::Display for Err {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("b")
        }
    }
}

pub struct Plain;

impl ToJson for Plain {
    fn to_json(&self) -> String {
        String::new()
    }
}

pub fn default_dyn(j: &dyn ToJson<()>) -> String {
    j.to_json()
}

pub fn default_qualified(p: &Plain) -> String {
    <Plain as ToJson<()>>::to_json(p)
}

pub struct Holder;

impl Holder {
    pub fn method_generic<C>(&self, j: &dyn ToJson<C>) -> String {
        j.to_json()
    }
}

pub struct Pathed;

impl tj::Pair<crate::ApiCtx, u8> for Pathed {
    fn pair(&self) -> u8 {
        2
    }
}

pub fn pathed(p: &Pathed) -> u8 {
    <Pathed as tj::Pair<ApiCtx, u8>>::pair(p)
}

pub struct Named;

impl<'a> tj::Pair<&'a str, u8> for Named {
    fn pair(&self) -> u8 {
        3
    }
}

pub fn named_dyn(n: &Named) -> u8 {
    let j: &dyn tj::Pair<&'static str, u8> = n;
    j.pair()
}

pub struct Wrapper<T>(pub T);

impl<T> ToJson<ApiCtx> for Wrapper<T> {
    fn to_json(&self) -> String {
        String::new()
    }
}

pub fn via_client_wrapped(id: Uuid) -> String {
    Client::<ApiCtx>::new().enc(&Wrapper(id))
}
