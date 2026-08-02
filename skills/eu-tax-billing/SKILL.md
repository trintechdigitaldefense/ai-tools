---
name: eu-tax-billing
description: EU tax, VAT, billing, invoicing, quotes, reverse-charge, OSS, and accountant-ready summaries for freelancers, contractors, solo founders, and small teams across all 27 EU countries.
---
# EU Tax & Billing

Use this skill for practical **EU billing and tax-admin** work: VAT treatment, invoice/quote drafting, reverse charge, OSS, small-business no-VAT wording, freelancer/company billing differences, and accountant-ready summaries.

## Scope

Designed for:
- freelancers
- solo entrepreneurs
- contractors
- micro-agencies
- small remote teams
- indie founders operating in or billing into the EU

Typical tasks:
- explain VAT treatment for a client or transaction
- explain billing-relevant sole trader vs company differences
- explain cross-border EU invoicing rules
- generate a quote / estimate
- generate an invoice
- draft a tax summary or accountant handoff report
- check whether an invoice is missing critical compliance details

Out of scope unless the user only needs billing/VAT implications:
- employment disputes or general labor law
- immigration / visas
- privacy / GDPR
- litigation
- licensing / regulatory approvals

## Guardrails

This skill is **guidance, not regulated legal or tax advice**.

Always:
- state assumptions clearly
- mention seller country, customer country, and customer type (B2B/B2C)
- flag uncertainty when facts are missing
- recommend local accountant / tax advisor review for high-risk cases
- distinguish **mandatory / likely required** vs **optional / commonly useful** fields

Never:
- invent tax rates, thresholds, or filing deadlines
- say something is definitively compliant if key facts are missing
- guess that fields such as phone, email, VAT ID, registration number, or bank details are mandatory unless the relevant country file supports it
- hide country-specific complexity

## Country-file requirement

Before giving **country-specific** billing or VAT guidance, read:
- `references/countries/README.md`
- the **seller-country** file whenever covered
- the **customer-country** file as well when cross-border and covered

If a file says a threshold, filing rhythm, wording, e-invoicing phase, or regime may have changed, say so plainly and avoid overclaiming.

## Required input checklist

Before answering, collect or infer the minimum needed:
- seller country
- customer country
- B2B or B2C
- seller VAT-registered or not
- business type (sole trader / company / contractor)
- service or goods type
- invoice currency
- tax year or transaction date

If key facts are missing, ask only for the minimum needed to proceed.

## Document-generation workflow

Before generating a **quote or invoice**:
1. Ask for the **seller's professional information first**.
2. Read `references/invoice-quote-inputs.md`.
3. Read the relevant country file(s).
4. Separate requested fields into:
   - **likely mandatory / core for the draft**
   - **optional / commonly useful**
5. If the country note does not clearly support a field as mandatory, say that verification may be needed.

## Output modes

### 1) Compliance guidance
Use this structure:
1. **Short answer**
2. **Why**
3. **Assumptions**
4. **What to put on the invoice / quote**
5. **What to verify with an accountant**

### 2) Invoice generation
Produce:
- seller details
- customer details
- invoice number
- issue date
- due date
- line items
- subtotal
- VAT treatment
- total due
- payment terms
- compliance note if needed

Use a clean format. If the user wants a file, write it to the workspace.

### 3) Quote / estimate generation
Produce:
- quote number
- issue date
- validity date
- seller / customer details
- line items
- subtotal
- VAT handling
- total estimate
- scope / exclusions if relevant

### 4) Tax / accountant report
Organize as:
- period covered
- revenue total
- VATable domestic sales
- intra-EU B2B reverse-charge sales
- intra-EU B2C / OSS relevant sales
- expenses by category
- invoices issued / paid / unpaid
- possible risk flags
- open questions for accountant

## Invoice and quote compliance checklist

At minimum, generated documents should usually include:
- unique document number
- issue date
- seller legal name and address
- customer legal name and address
- description of services or goods
- amount per line
- subtotal
- VAT rate or exemption handling
- total
- payment terms

For EU B2B reverse charge, typical wording is:
- `Reverse charge — Article 196 of Council Directive 2006/112/EC`

If VAT IDs, registration numbers, or local exemption wording may matter, ask for them or mark them for verification rather than guessing.

## Practical rules of thumb

- **Cross-border EU B2B services** often use reverse charge if both parties are taxable businesses and the place of supply is the customer's country.
- **Cross-border EU B2C digital services** may trigger destination-country VAT and OSS.
- **Domestic invoicing** usually follows local VAT rules.
- **Missing country / VAT status / B2B-vs-B2C facts** means the answer is provisional.
- **Local wording matters**: small-business exemption text, reverse-charge wording, and quote wording can differ by country.

Do not over-generalize these rules without reading the relevant country note.

## File outputs

When asked to generate documents, prefer writing files in:
- `workspace/documents/quotes/`
- `workspace/documents/invoices/`
- `workspace/documents/reports/`

Useful formats:
- Markdown (`.md`) for editable drafts
- CSV for simple exports
- JSON for structured bookkeeping / integrations

## References

See:
- `references/invoice-quote-inputs.md`
- `references/invoice-template.md`
- `references/quote-template.md`
- `references/tax-summary-template.md`
- `references/countries/README.md`

## Escalation triggers

Tell the user to verify with a local accountant or tax advisor when:
- payroll / employment law is involved
- permanent-establishment risk appears
- VAT registration status is unclear
- OSS / IOSS edge cases appear
- multiple EU countries are involved and the facts are incomplete
- corporate structuring or tax optimization is requested
- local filing deadlines, thresholds, or e-invoicing obligations may have changed
