# Invoice / quote input collection

Use this before generating a quote or invoice.

## Rule
Ask for the **seller's professional information first** before drafting the document.

Do not guess whether fields such as phone number, email, VAT ID, company registration number, or bank details are mandatory unless the relevant country file supports that conclusion.

## Minimum working input set

### Likely mandatory or core fields
Collect these first:
- seller legal name
- seller address
- seller VAT ID **if relevant / if VAT-registered**
- seller company registration number **if relevant / if the country file says it matters**
- customer legal name
- customer address
- customer VAT ID **if relevant for B2B / reverse-charge / intra-EU handling**
- invoice number or quote number
- issue date
- due date **for invoices** / validity date **for quotes**
- line items with description, quantity/rate, and amount
- currency
- payment terms or timing

### Often useful but not always mandatory
Add when the user wants them or when commercially useful:
- seller email
- seller phone
- customer contact person
- PO number / reference number
- bank details / IBAN / payment link
- service period or delivery date
- notes
- scope assumptions / exclusions
- deposit schedule / milestones
- late-payment note

## Collection workflow
1. Confirm seller country.
2. Read the seller-country file.
3. If cross-border, confirm customer country and read that file too when covered.
4. Ask only for the fields needed to draft a compliant first version.
5. Separate the answer into:
   - **likely mandatory / core for this draft**
   - **optional / commonly useful**
6. If the relevant country file does not clearly support a field as mandatory, say that verification may be needed.

## Ready-to-use checklist

### Seller
- legal name
- full address
- country
- VAT ID if relevant
- company registration number if relevant
- legal form if useful

### Customer
- legal name
- full address
- country
- VAT ID if relevant

### Document
- invoice / quote number
- issue date
- due date or validity date
- currency
- payment terms

### Commercial lines
- description of goods/services
- quantity / unit price / fixed fee
- subtotal
- VAT treatment
- total

### Optional extras
- email
- phone
- PO number
- bank details
- notes
- scope / exclusions
- milestone schedule
