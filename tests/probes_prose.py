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
