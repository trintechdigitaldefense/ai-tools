# Invoice Template

```md
# Invoice {{invoice_number}}

**Seller**
- Name: {{seller_name}}
- Address: {{seller_address}}
- VAT ID: {{seller_vat_id}}

**Customer**
- Name: {{customer_name}}
- Address: {{customer_address}}
- VAT ID: {{customer_vat_id}}

**Issue date:** {{issue_date}}
**Due date:** {{due_date}}
**Currency:** {{currency}}

## Line items
| Description | Qty | Unit price | Amount |
|---|---:|---:|---:|
| {{item_1_description}} | {{item_1_qty}} | {{item_1_unit_price}} | {{item_1_amount}} |

**Subtotal:** {{subtotal}}
**VAT:** {{vat_amount}} {{vat_note}}
**Total due:** {{total_due}}

**Payment terms**
{{payment_terms}}

**Compliance note**
{{compliance_note}}
```

## Notes
- Use a unique sequential invoice number.
- For reverse-charge B2B services, include the applicable reverse-charge wording.
- If VAT IDs matter and are missing, ask for them or mark as pending verification.
