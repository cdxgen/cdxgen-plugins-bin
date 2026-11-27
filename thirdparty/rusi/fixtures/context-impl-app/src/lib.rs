// Reproducer for trait impls under a context marker type: a trait with a
// defaulted context parameter, implemented for a foreign type under local
// marker types. Serializers and codecs built this way call user code
// through these impls, which is where a source-to-sink flow passes.
use std::process::Command;

pub mod probes;

use context_impl_tojson::{Client, Pair, ToJson};
use fakeuuid::Uuid;

pub struct ApiCtx;
pub struct RpcCtx;

impl ToJson<ApiCtx> for Uuid {
    fn to_json(&self) -> String {
        let out = Command::new("sh")
            .arg("-c")
            .arg(self.to_string())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl ToJson<RpcCtx> for Uuid {
    fn to_json(&self) -> String {
        std::fs::write("rpc.json", self.to_string()).ok();
        format!("{}", self.as_u128())
    }
}

impl<T> Pair<ApiCtx, T> for Uuid {
    fn pair(&self) -> u8 {
        1
    }
}

pub struct Product {
    pub id: Uuid,
    pub qty: i32,
}

impl<Ctx> ToJson<Ctx> for Product
where
    Uuid: ToJson<Ctx>,
    i32: ToJson<Ctx>,
{
    fn to_json(&self) -> String {
        format!(
            "{}{}",
            <Uuid as ToJson<Ctx>>::to_json(&self.id),
            ToJson::<Ctx>::to_json(&self.qty)
        )
    }
}

pub struct MyUuid(pub Uuid);

impl ToJson for MyUuid {
    fn to_json(&self) -> String {
        self.0.to_string()
    }
}

pub fn api(p: &Product) -> String {
    <Product as ToJson<ApiCtx>>::to_json(p)
}

pub fn rpc(id: Uuid) -> String {
    ToJson::<RpcCtx>::to_json(&id)
}

pub fn method_api(id: Uuid) -> String {
    let j: &dyn ToJson<ApiCtx> = &id;
    j.to_json()
}

pub fn plain_method(id: Uuid) -> String {
    let x: &dyn ToJson<RpcCtx> = &id;
    x.to_json()
}

pub fn via_client(id: Uuid) -> String {
    Client::<()>::new().codec::<ApiCtx>().enc(&id)
}

pub fn newtype(id: Uuid) -> String {
    MyUuid(id).to_json()
}

pub fn pair(id: Uuid) -> u8 {
    <Uuid as Pair<ApiCtx, u8>>::pair(&id)
}

pub fn handler() -> String {
    let raw = std::env::var("ID").unwrap();
    let id = Uuid::parse_str(&raw).unwrap();
    api(&Product { id, qty: 1 })
}

pub fn handler2() -> String {
    let raw = std::env::var("ID").unwrap();
    let id = Uuid::parse_str(&raw).unwrap();
    via_client(id)
}

pub fn api_direct() -> String {
    let raw = std::env::var("ID").unwrap();
    let id = Uuid::parse_str(&raw).unwrap();
    <Uuid as ToJson<ApiCtx>>::to_json(&id)
}

pub fn rpc_direct() -> String {
    let raw = std::env::var("ID").unwrap();
    let id = Uuid::parse_str(&raw).unwrap();
    <Uuid as ToJson<RpcCtx>>::to_json(&id)
}
