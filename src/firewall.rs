use crate::admin::ps;
#[derive(Clone,Debug)]
pub struct Rule{pub name:String,pub direction:String,pub action:String,pub enabled:String}
pub fn rules()->anyhow::Result<Vec<Rule>>{
    let s=ps("Get-NetFirewallRule | Select -First 500 DisplayName,Direction,Action,Enabled | ConvertTo-Json -Compress")?;
    if s.is_empty(){return Ok(vec![])}
    let v:serde_json::Value=serde_json::from_str(&s)?;
    let a=if v.is_array(){v.as_array().cloned().unwrap_or_default()}else{vec![v]};
    Ok(a.into_iter().map(|x|Rule{name:x["DisplayName"].as_str().unwrap_or("").into(),direction:x["Direction"].as_str().unwrap_or("").into(),action:x["Action"].as_str().unwrap_or("").into(),enabled:x["Enabled"].as_str().unwrap_or("").into()}).collect())
}
pub fn add(name:&str,port:u16,proto:&str)->anyhow::Result<()>{
    ps(&format!("New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Action Allow -Protocol {} -LocalPort {} -Profile Private",name.replace("'","''"),proto,port))?; Ok(())
}
pub fn remove(name:&str)->anyhow::Result<()>{
    ps(&format!("Remove-NetFirewallRule -DisplayName '{}' -Confirm:$false",name.replace("'","''")))?; Ok(())
}
