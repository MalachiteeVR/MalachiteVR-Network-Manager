use crate::admin::ps;
use serde::Deserialize;

#[derive(Clone,Debug,Deserialize)]
pub struct Adapter {
    #[serde(rename="Name")] pub name:String,
    #[serde(rename="InterfaceDescription")] pub description:String,
    #[serde(rename="Status")] pub status:String,
    #[serde(rename="LinkSpeed")] pub speed:String,
    #[serde(rename="MacAddress")] pub mac:Option<String>,
}
pub fn adapters()->anyhow::Result<Vec<Adapter>> {
    let s=ps("Get-NetAdapter | Select Name,InterfaceDescription,Status,@{N='LinkSpeed';E={$_.LinkSpeed}},MacAddress | ConvertTo-Json -Compress")?;
    if s.is_empty(){return Ok(vec![])}
    let v:serde_json::Value=serde_json::from_str(&s)?;
    Ok(if v.is_array(){serde_json::from_value(v)?}else{vec![serde_json::from_value(v)?]})
}
pub fn toggle(name:&str,on:bool)->anyhow::Result<()>{
    let n=name.replace("'","''");
    ps(&format!("{}-NetAdapter -Name '{}' -Confirm:$false",if on{"Enable"}else{"Disable"},n))?; Ok(())
}
pub fn connections()->anyhow::Result<String>{
    ps("Get-NetTCPConnection | Sort State,RemotePort | Select -First 300 | Format-Table -AutoSize | Out-String -Width 240")
}
