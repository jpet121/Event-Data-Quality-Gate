use crate::engine::utc_timestamp;
use crate::json::{Decimal, Object, Value};
use std::collections::BTreeSet;

fn identifier(text: Option<&str>) -> bool {
    text.is_some_and(|s| {
        (1..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    })
}

fn text<'a>(value: &'a Object, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::string)
}

fn number<'a>(value: Option<&'a Object>, name: &str) -> Option<&'a str> {
    value?.get(name)?.number()
}

pub(crate) fn evaluate(envelope: &Object, emit: &mut dyn FnMut(&str, String) -> bool) {
    let Some(data) = envelope.get("data").and_then(Value::object) else {
        emit("ORDER-IDENTITY", "/data".into());
        return;
    };
    let Some(items) = data.get("items").and_then(Value::array) else {
        emit("ORDER-IDENTITY", "/data/items".into());
        return;
    };
    let mut identity = vec![
        ("/data/order_id".into(), identifier(text(data, "order_id"))),
        ("/id".into(), identifier(text(envelope, "id"))),
        (
            "/source".into(),
            text(envelope, "source") == Some("alderquay.order-adapter"),
        ),
    ];
    let mut numbers = vec![(
        "/data/total_minor".into(),
        number(Some(data), "total_minor"),
    )];
    for (index, item) in items.iter().enumerate() {
        let item = item.object();
        for name in ["line_id", "sku"] {
            identity.push((
                format!("/data/items/{index}/{name}"),
                identifier(item.and_then(|fields| text(fields, name))),
            ));
        }
        for name in ["quantity", "unit_price_minor"] {
            numbers.push((format!("/data/items/{index}/{name}"), number(item, name)));
        }
    }
    identity.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    numbers.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    for (path, ok) in identity {
        if !ok && !emit("ORDER-IDENTITY", path) {
            return;
        }
    }
    for (path, number) in numbers {
        let plain = number.is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()));
        if !plain && !emit("ORDER-INTEGER-TOKENS", path) {
            return;
        }
    }
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        if let Some(id) = item.object().and_then(|fields| text(fields, "line_id"))
            && !seen.insert(id)
            && !emit("ORDER-LINE-UNIQUE", format!("/data/items/{index}/line_id"))
        {
            return;
        }
    }
    if !text(data, "occurred_at").is_some_and(utc_timestamp)
        && !emit("ORDER-TIME", "/data/occurred_at".into())
    {
        return;
    }
    let subtotal = items.iter().try_fold(0_u64, |total, item| {
        let item = item.object();
        let quantity = Decimal::new(number(item, "quantity")?).to_u64()?;
        let unit_price = Decimal::new(number(item, "unit_price_minor")?).to_u64()?;
        total.checked_add(quantity.checked_mul(unit_price)?)
    });
    let supplied = number(Some(data), "total_minor").and_then(|value| Decimal::new(value).to_u64());
    if subtotal.is_none() || subtotal != supplied {
        emit("ORDER-TOTAL", "/data/total_minor".into());
    }
}
