const KISA_CATALOG_SCHEMES = [
  {
    prefix: "INP",
    start: 1,
    end: 17,
  },
  {
    prefix: "SEC",
    start: 18,
    end: 33,
  },
  {
    prefix: "TIM",
    start: 34,
    end: 35,
  },
  {
    prefix: "ERR",
    start: 36,
    end: 38,
  },
  {
    prefix: "COD",
    start: 39,
    end: 43,
  },
  {
    prefix: "ENC",
    start: 44,
    end: 47,
  },
  {
    prefix: "API",
    start: 48,
    end: 49,
  },
];


export function getKisaCatalogIdentifierByItemNumber(
  itemNumber
) {

  const normalizedItemNumber =
    Number(
      itemNumber
    );


  if (
    !Number.isInteger(
      normalizedItemNumber
    )
  ) {

    return "";
  }


  const scheme =
    KISA_CATALOG_SCHEMES.find(
      ({ start, end }) =>
        normalizedItemNumber >= start &&
        normalizedItemNumber <= end
    );


  if (!scheme) {

    return "";
  }


  const localNumber =
    normalizedItemNumber -
    scheme.start +
    1;


  return (
    `KISA-${scheme.prefix}-${String(
      localNumber
    ).padStart(
      2,
      "0"
    )}`
  );
}


function getKisaItemNumberFromRuleId(
  ruleId
) {

  const ruleMatch =
    String(
      ruleId ||
      ""
    ).match(
      /^kisa\.sw(\d{1,2})(?:\.|$)/i
    );


  if (!ruleMatch) {

    return null;
  }


  const itemNumber =
    Number(
      ruleMatch[1]
    );


  return (
    Number.isInteger(
      itemNumber
    )
      ? itemNumber
      : null
  );
}


export function getSecurityWeaknessIdentifier(
  vulnerability
) {

  const directIdentifier =
    vulnerability
      ?.securityWeaknessIdentifier ||
    vulnerability
      ?.security_weakness_identifier ||
    "";


  if (directIdentifier) {

    return directIdentifier;
  }


  const itemNumber =
    vulnerability
      ?.securityWeaknessItemNumber ??
    vulnerability
      ?.security_weakness_item_number ??
    getKisaItemNumberFromRuleId(
      vulnerability?.ruleId ||
      vulnerability?.rule_id
    );


  return (
    getKisaCatalogIdentifierByItemNumber(
      itemNumber
    ) ||
    "-"
  );
}


export function getVulnerabilityDisplayName(
  vulnerability
) {

  const identifier =
    getSecurityWeaknessIdentifier(
      vulnerability
    );

  const name =
    vulnerability?.name ||
    "-";


  return (
    identifier !== "-"
      ? `${identifier} · ${name}`
      : name
  );
}
