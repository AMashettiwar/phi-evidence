"""Prose shapes written independently of the corpus generator.

The corpus held-out split turned out to hold whole templates the detector never
saw, and recall there was 0.50. These probes are new text, written to find
general weaknesses without looking at a single held-out item. Each positive
names a person and a health fact in one record; each negative must stay clean.
"""

POSITIVES = [
    ("Ana Ruiz", "Reminder for Ana Ruiz: your colonoscopy is booked for Tuesday at 9:00."),
    ("Tomas Berg", "Lab result: Tomas Berg, HbA1c 9.1% (high), fasting glucose 182 mg/dL."),
    ("Priya Nair", "Priya Nair is 32 weeks pregnant and attends the antenatal clinic."),
    ("Jonas Weber", "Prescription renewed for Jonas Weber: sertraline 100 mg daily."),
    ("Leila Haddad", "\"I never thought I'd beat lymphoma,\" says Leila Haddad, 44."),
    ("Marcus Hale", "My name is Marcus Hale and I have lived with bipolar disorder for ten years."),
    ("Chloe Martin", "Chloe Martin's knee replacement went well; physiotherapy starts Monday."),
    ("Ibrahim Saleh", "Post-op note: Ibrahim Saleh, laparoscopic cholecystectomy, no complications."),
    ("Grace O'Neill", "Thank you to Grace O'Neill for sharing her journey through chemotherapy."),
    ("Diego Alvarez", "Admitted overnight: Diego Alvarez with community-acquired pneumonia."),
    ("Hannah Schmidt", "Hannah Schmidt tested positive for chlamydia and was treated with doxycycline."),
    ("Kofi Mensah", "Patient Kofi Mensah, 67, dialysis three times weekly for end-stage renal disease."),
    ("Yuki Sato", "Yuki Sato completed her IVF cycle last month."),
    ("Oliver Grant", "Oliver Grant was referred to the memory clinic with suspected Alzheimer's disease."),
    ("Sofia Rossi", "Discharge summary - Sofia Rossi - acute appendicitis, appendectomy performed."),
    ("Ethan Brooks", "We are raising funds for Ethan Brooks, who has leukaemia."),
    ("Nadia Petrova", "Nadia Petrova attends our weekly group for alcohol use disorder."),
    ("Lucas Moreau", "Vaccination record: Lucas Moreau received the hepatitis B series."),
    ("Amelia Clarke", "Amelia Clarke is recovering from a stroke on the rehabilitation ward."),
    ("Rahul Mehta", "Rahul Mehta's MRI shows a herniated disc at L4-L5."),
    ("Isabel Ortiz", "Get well soon, Isabel Ortiz! Our thoughts are with you after your mastectomy."),
    ("Victor Lindqvist", "Victor Lindqvist has started insulin for type 1 diabetes."),
    ("Mei Chen", "Counselling session notes, Mei Chen: panic attacks have reduced since starting therapy."),
    ("Samuel Okoro", "Samuel Okoro is on the transplant list awaiting a kidney."),
    ("Laura Bianchi", "The HIV clinic will see Laura Bianchi on Friday for her viral load test."),
    ("Noah Fischer", "Noah Fischer: epilepsy, last seizure March, levetiracetam continued."),
    ("Zara Ahmed", "Zara Ahmed was treated for an eating disorder at our adolescent unit."),
    ("Henrik Larsen", "Henrik Larsen underwent cardiac catheterisation and stenting yesterday."),
    ("Olivia Turner", "Olivia Turner's biopsy confirmed melanoma; surgery is planned."),
    ("Mateo Silva", "Physio appointment: Mateo Silva, rotator cuff tear, session 4 of 10."),
]

NEGATIVES = [
    "Colonoscopy is recommended every ten years from age 45.",
    "Our team includes Dr. Ana Ruiz, a gastroenterologist with 15 years of experience.",
    "Meet Tomas Berg, our new IT manager, who joins us from Oslo.",
    "Sertraline is a common treatment for depression and anxiety.",
    "Grace O'Neill will lead the charity run on Saturday.",
    "Knee replacement recovery usually takes six to twelve weeks.",
    "Contact Leila Haddad in the communications office for press enquiries.",
    "In 2025 we performed 1,320 knee replacements.",
    "Join Marcus Hale and Priya Nair at the summer volunteer picnic.",
    "Melanoma awareness month starts in May; book a free skin check.",
]

# One visual record spread over several elements (written after G5 run 3 to
# test a layout hypothesis, without opening a held-out item). Label/value spans
# in sibling <div>s with no shared container are a stated limit, not probed.
LAYOUT_NAME = "Rowan Ellis"
LAYOUTS = {
    "card": "<div class='card'><h3>Rowan Ellis</h3><p>chronic kidney disease</p></div>",
    "definition_list": "<dl><dt>Patient</dt><dd>Rowan Ellis</dd><dt>Diagnosis</dt><dd>chronic kidney disease</dd></dl>",
    "line_breaks": "<p>Patient: Rowan Ellis<br>Diagnosis: chronic kidney disease</p>",
    "section": "<section><h2>Rowan Ellis</h2><p>Living with chronic kidney disease.</p></section>",
    "nested_list_item": "<ul><li><strong>Rowan Ellis</strong><p>chronic kidney disease</p></li></ul>",
    "figure_alt": "<figure><img alt='Rowan Ellis' src='x.jpg'><figcaption>chronic kidney disease support group</figcaption></figure>",
    "article": "<article><h1>Rowan Ellis</h1><p>Diagnosed with chronic kidney disease in 2019.</p></article>",
}

# Consented testimonials laid out in different ways (written after G5 run 4,
# without opening a held-out item). Each must stay clean; the last control
# has a note between two stories, which belongs only to the story before it.
CONSENT_STORY = "Priya Nair shares how she manages type 2 diabetes every day."
CONSENT_LAYOUTS = {
    "p_em": f"<p>{CONSENT_STORY} <em>Shared with written permission.</em></p>",
    "p_then_small": f"<p>{CONSENT_STORY}</p><small>Names and details changed.</small>",
    "div_p_small": f"<div class='story'><p>{CONSENT_STORY}</p><small>Shared with permission</small></div>",
    "blockquote_footer": f"<blockquote><p>{CONSENT_STORY}</p><footer>Published with consent</footer></blockquote>",
    "blockquote_then_p": f"<blockquote><p>{CONSENT_STORY}</p></blockquote><p>Shared with permission.</p>",
    "nested_list_item": f"<ul><li><p>{CONSENT_STORY}</p><span>Shared with permission</span></li></ul>",
    "figure_after": "<figure><figcaption>Priya Nair, living with type 2 diabetes</figcaption></figure><small>Fictional account</small>",
    "table_row": "<table><tr><td>Priya Nair</td><td>type 2 diabetes</td><td>Shared with permission</td></tr></table>",
    "definition_list": f"<dl><dt>Story</dt><dd>{CONSENT_STORY}</dd><dt>Consent</dt><dd>Shared with written permission</dd></dl>",
    "note_before": f"<p><strong>Shared with permission</strong></p><p>{CONSENT_STORY}</p>",
}
TWO_STORIES = (f"<p>{CONSENT_STORY}</p><p>Shared with permission.</p>"
               "<p>Ana Ruiz manages asthma with an inhaler.</p><p>Thanks for reading.</p>")

# Multi-block records with the note beside them (written after G5 run 5).
MULTI_BLOCK_CONSENT = {
    "article_after_note": f"<article><h2>Priya Nair</h2><p>{CONSENT_STORY}</p></article><p>Shared with permission.</p>",
    "card_after_note": f"<div class='card'><h3>Priya Nair</h3><p>{CONSENT_STORY}</p></div><small>Names changed</small>",
    "list_item_after": f"<ul><li><strong>Priya Nair</strong><p>{CONSENT_STORY}</p></li></ul><p>Shared with written permission.</p>",
    "figure_after": f"<figure><img alt='Priya Nair' src='p.jpg'><figcaption>{CONSENT_STORY}</figcaption></figure><p>Fictional account.</p>",
    "card_wrapped_note": f"<div class='story'><div class='card'><h3>Priya Nair</h3><p>{CONSENT_STORY}</p></div><p>Shared with permission</p></div>",
}
CARD_WITHOUT_NOTE = f"<div class='card'><h3>Priya Nair</h3><p>{CONSENT_STORY}</p></div><small>Updated May 2026</small>"

# Disclosed (eval/disclosures.md): taken from the held-out N8 template after
# G5 run 6, at the owner's decision. A quotation whose speaker sits in an
# inline <cite> with no space before it, and a consent note in the next block.
CITE_QUOTE = ('<blockquote>"I live with type 2 diabetes. The support group helped."'
              '<cite>Priya Nair</cite></blockquote><p>Published with the person\'s consent.</p>')
CITE_QUOTE_NO_NOTE = ('<blockquote>"I live with type 2 diabetes. The support group helped."'
                      '<cite>Priya Nair</cite></blockquote><p>Thanks for reading.</p>')
