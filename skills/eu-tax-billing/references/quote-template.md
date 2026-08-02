# Quote Template

```md
# Quote {{quote_number}}

**Seller**
- Name: {{seller_name}}
- Address: {{seller_address}}
- VAT ID: {{seller_vat_id}}

**Customer**
- Name: {{customer_name}}
- Address: {{customer_address}}
- VAT ID: {{customer_vat_id}}

**Issue date:** {{issue_date}}
**Valid until:** {{valid_until}}
**Currency:** {{currency}}

## Scope
{{scope_summary}}

## Line items
| Description | Qty | Unit price | Amount |
|---|---:|---:|---:|
| {{item_1_description}} | {{item_1_qty}} | {{item_1_unit_price}} | {{item_1_amount}} |

**Subtotal:** {{subtotal}}
**VAT:** {{vat_amount}} {{vat_note}}
**Total estimate:** {{total_estimate}}

## Terms
{{terms}}
```

## Notes
- Quotes should include validity date and scope boundaries.
- If VAT treatment is uncertain, label it as provisional pending confirmation.
