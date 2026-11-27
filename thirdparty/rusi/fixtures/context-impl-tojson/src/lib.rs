// Stands in for a library that owns a trait with a defaulted context
// parameter, the orphan-rule workaround the context-impl-app fixture
// exercises. The dependency tier analyzes it as a separate crate.
pub trait ToJson<Ctx = ()> {
    fn to_json(&self) -> String;
}

impl<Ctx> ToJson<Ctx> for i32 {
    fn to_json(&self) -> String {
        self.to_string()
    }
}

pub trait Pair<A, B> {
    fn pair(&self) -> u8;
}

pub struct Client<X> {
    _m: core::marker::PhantomData<X>,
}

impl<X> Client<X> {
    pub fn new() -> Self {
        Client {
            _m: core::marker::PhantomData,
        }
    }
    pub fn codec<Y>(self) -> Client<Y> {
        Client {
            _m: core::marker::PhantomData,
        }
    }
    pub fn enc<T: ToJson<X>>(&self, t: &T) -> String {
        t.to_json()
    }
}
