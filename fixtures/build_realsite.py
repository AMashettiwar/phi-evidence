#!/usr/bin/env python3
"""A realistic hospital website: the pages real health-system sites carry that
look like patient data and are not, plus planted leaks in those same pages.

Why it exists: the first real application scanned gave 12 false alarms the
synthetic world never produced, because the world has no real-site furniture.
This site is that furniture, page type by page type:

    doctor directory, doctor bios (title, URL slug, JSON-LD, NPI), a provider
    directory API, a sitemap listing every doctor, health-library articles with
    author and medical-reviewer bylines, a press release, clinical-trial
    listings with investigators, a job posting, a support-group event, a
    sample insurance card, FHIR developer docs with the specification's own
    example patient, a notice of privacy practices, the WordPress users
    endpoint, tag-manager and analytics snippets, a consented patient story.

Everything below is fictional. Every planted leak is recorded in
fixtures/realsite/key.json with the value a finding must carry; anything else
the scanner reports here is a false alarm (tools/check_realsite.py).

Run:  python fixtures/build_realsite.py
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "realsite"
SITE = ROOT / "site"
KEY: list[dict] = []

GTM = """<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-K7Q2X9M');</script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-4TQ8L2ZP1V"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}
gtag('js',new Date());gtag('config','G-4TQ8L2ZP1V',{anonymize_ip:true});</script>"""

NAV = """<header class="site-header"><a class="logo" href="/">Mercy Valley Health</a>
<nav><a href="/find-a-doctor/">Find a Doctor</a> <a href="/locations/">Locations</a>
<a href="/health-library/">Health Library</a> <a href="/research/clinical-trials.html">Clinical Trials</a>
<a href="/careers/">Careers</a> <a href="/patient-portal/">MyChart Login</a></nav></header>"""

FOOTER = """<footer class="site-footer"><address>Mercy Valley Health, 2200 Orchard Parkway,
Riverton, OH 45810 &middot; Main line 555-0100 &middot; info@mercyvalley.example</address>
<p><a href="/notice-of-privacy-practices.html">Notice of Privacy Practices</a> &middot;
<a href="/nondiscrimination.html">Nondiscrimination</a> &middot; &copy; 2025 Mercy Valley Health</p>
<div class="cookie-banner" role="dialog">We use cookies to improve your experience.
<button>Accept</button> <button>Manage preferences</button></div></footer>"""


def page(title: str, body: str, head: str = "", description: str = "") -> str:
    meta = f'<meta name="description" content="{description}">' if description else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>{meta}
<meta property="og:site_name" content="Mercy Valley Health">{head}{GTM}
<link rel="stylesheet" href="/assets/site.css"></head><body>{NAV}<main>{body}</main>{FOOTER}
<script src="/assets/site.js"></script></body></html>
"""


def write(relative: str, content: str) -> None:
    target = SITE / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")


def plant(relative: str, value: str, why: str) -> None:
    KEY.append({"path": relative, "value": value, "why": why})


def npi(base9: str) -> str:
    """A valid NPI: Luhn over the 80840 prefix, as CMS defines it."""
    digits = [int(c) for c in "80840" + base9]
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 0:
            digit *= 2
            digit = digit - 9 if digit > 9 else digit
        total += digit
    return base9 + str((10 - total % 10) % 10)


DOCTORS = [
    ("amara-okafor", "Amara Okafor", "MD", "Cardiology", "heart failure, atrial fibrillation and high blood pressure", "123456781"[:9]),
    ("samuel-ortiz", "Samuel Ortiz", "MD, PhD", "Endocrinology", "type 2 diabetes, thyroid disease and osteoporosis", "234567890"),
    ("lena-fischer", "Lena Fischer", "DO", "Oncology", "breast cancer, lung cancer and lymphoma", "345678901"),
    ("priya-raman", "Priya Raman", "MD", "Family Medicine", "asthma, depression and preventive care", "456789012"),
]


def build() -> None:
    shutil.rmtree(ROOT, ignore_errors=True)

    write("index.html", page(
        "Mercy Valley Health | Hospitals, Doctors and Care in Riverton, Ohio",
        """<section class="hero"><h1>Care that comes to you</h1><p>Same-day appointments for
adults and children at 14 locations.</p></section>
<section class="news"><h2>Latest news</h2><ul>
<li><a href="/news/2025-cancer-center.html">Mercy Valley opens the Fischer Family Cancer Center</a>
<span class="byline">By Jordan Lee &middot; March 3, 2025</span></li>
<li><a href="/health-library/type-2-diabetes.html">Type 2 diabetes: what to know</a>
<span class="byline">Medically reviewed by Priya Raman, MD</span></li></ul></section>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Hospital",
"name":"Mercy Valley Health","telephone":"555-0100","address":{"@type":"PostalAddress",
"streetAddress":"2200 Orchard Parkway","addressLocality":"Riverton","addressRegion":"OH",
"postalCode":"45810"},"medicalSpecialty":["Cardiology","Oncology","Endocrinology"]}</script>""",
        description="Mercy Valley Health offers primary care, cancer care, heart care and "
                    "diabetes care across 14 locations in Riverton, Ohio."))

    cards = "".join(
        f"""<li class="provider-card" data-provider-id="{1020 + i}" data-npi="{npi(base)}"
data-name="{name}" data-specialty="{specialty}"><a href="/find-a-doctor/dr-{slug}.html">
<img src="/assets/headshots/{slug}.jpg" alt="Headshot of Dr. {name}"><h3>Dr. {name}, {cred}</h3></a>
<p class="specialty">{specialty}</p><p>Treats {conditions}.</p>
<p class="accepting">Accepting new patients &middot; 555-0123</p></li>"""
        for i, (slug, name, cred, specialty, conditions, base) in enumerate(DOCTORS))
    write("find-a-doctor/index.html", page(
        "Find a Doctor | Mercy Valley Health",
        f"""<h1>Find a doctor</h1><form action="/find-a-doctor/search" method="get">
<input name="q" placeholder="Name, specialty or condition"></form><ul class="results">{cards}</ul>""",
        description="Search Mercy Valley Health doctors by name, specialty or condition."))

    for i, (slug, name, cred, specialty, conditions, base) in enumerate(DOCTORS):
        last = name.split()[-1]
        reviews = ("<blockquote>Dr. " + last + " explained my diagnosis clearly and never "
                   "rushed me.</blockquote><p class=\"review-meta\">Verified patient &middot; 5 stars</p>")
        comment = ""
        if slug == "amara-okafor":
            # Planted: a case note left in a comment by whoever built the page.
            comment = "<!-- case photo for bio: Ellen Burke MRN 4471829, consent form still pending -->"
            plant(f"find-a-doctor/dr-{slug}.html", "4471829",
                  "a patient's record number left in an HTML comment on a doctor's bio")
        write(f"find-a-doctor/dr-{slug}.html", page(
            f"Dr. {name}, {cred} | {specialty} | Mercy Valley Health",
            f"""{comment}<article class="provider-bio"><h1>Dr. {name}, {cred}</h1>
<p class="specialty">{specialty}</p><p>Dr. {last} treats {conditions}. Dr. {last} sees patients at the
Orchard Parkway campus and offers telehealth visits.</p>
<h2>Education</h2><ul><li>Medical school: Ohio State University College of Medicine</li>
<li>Residency: Cleveland Clinic</li><li>Board certified in {specialty}</li></ul>
<h2>Patient reviews</h2><p>4.8 out of 5 from 212 patient reviews</p>{reviews}
<p>NPI {npi(base)}</p></article>""",
            head=f"""<meta name="author" content="Mercy Valley Health Marketing">
<link rel="canonical" href="https://www.mercyvalley.example/find-a-doctor/dr-{slug}.html">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"Physician",
"name":"Dr. {name}","medicalSpecialty":"{specialty}","identifier":"{npi(base)}",
"telephone":"555-0123"}}</script>""",
            description=f"Dr. {name}, {cred}, is a {specialty.lower()} doctor in Riverton, Ohio, "
                        f"who treats {conditions}."))

    write("api/providers.json", json.dumps({"total": len(DOCTORS), "providers": [
        {"id": 1020 + i, "npi": npi(base), "firstName": name.split()[0], "lastName": name.split()[1],
         "credentials": cred, "specialties": [specialty],
         "conditionsTreated": [c.strip() for c in conditions.replace(" and ", ", ").split(",")],
         "acceptingNewPatients": True, "phone": "555-0123",
         "profileUrl": f"/find-a-doctor/dr-{slug}.html"}
        for i, (slug, name, cred, specialty, conditions, base) in enumerate(DOCTORS)]}, indent=2))

    write("health-library/type-2-diabetes.html", page(
        "Type 2 Diabetes: Symptoms, Causes and Treatment | Mercy Valley Health",
        """<article><h1>Type 2 diabetes</h1>
<p class="byline">Medically reviewed by Priya Raman, MD, on March 3, 2025.<br>Written by Daniel Cho.</p>
<p>Type 2 diabetes affects about 38 million Americans. It happens when the body does not use
insulin well. Common symptoms are thirst, frequent urination and blurred vision.</p>
<h2>Treatment</h2><p>Treatment includes metformin, GLP-1 medicines such as semaglutide, diet and
exercise. Your doctor may check your HbA1c every three months.</p>
<p>Related: <a href="/events/diabetes-support-group.html">Diabetes support group</a></p></article>""",
        head="""<meta name="author" content="Daniel Cho">
<meta property="article:published_time" content="2025-03-03T09:00:00-05:00">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"MedicalWebPage",
"about":{"@type":"MedicalCondition","name":"Type 2 diabetes"},
"author":{"@type":"Person","name":"Daniel Cho"},
"reviewedBy":{"@type":"Person","name":"Priya Raman","honorificSuffix":"MD"},
"lastReviewed":"2025-03-03"}</script>""",
        description="Learn about type 2 diabetes symptoms, causes and treatment, "
                    "reviewed by Priya Raman, MD."))

    write("news/2025-cancer-center.html", page(
        "Mercy Valley opens the Fischer Family Cancer Center | Mercy Valley Health",
        """<article><h1>Mercy Valley opens the Fischer Family Cancer Center</h1>
<p class="byline">By Jordan Lee &middot; March 3, 2025</p>
<p>RIVERTON, Ohio &mdash; Mercy Valley Health today opened a cancer center that will treat
about 4,000 patients a year with breast, lung and colon cancer. Dr. Lena Fischer, DO, will lead
the center as chief of oncology.</p>
<p>&ldquo;Our community deserves world-class cancer care close to home,&rdquo; said Marcus Webb,
president and CEO of Mercy Valley Health.</p>
<p><strong>Media contact:</strong> Jordan Lee, communications manager, 555-0142,
media@mercyvalley.example</p></article>""",
        head='<meta name="author" content="Jordan Lee">',
        description="Dr. Lena Fischer will lead the new cancer center, which will treat "
                    "breast, lung and colon cancer."))

    trial = """<li class="trial"><h3>NCT05512345: Weekly semaglutide in adults with type 2 diabetes
and chronic kidney disease</h3><p>Principal investigator: Dr. Samuel Ortiz, MD, PhD.
Study contact: Grace Kim, research coordinator, 555-0177.</p><p>Status: recruiting adults
aged 40 to 75.</p></li>"""
    write("research/clinical-trials.html", page(
        "Clinical Trials | Mercy Valley Health",
        f"""<h1>Clinical trials</h1><p>Mercy Valley takes part in 38 open studies.</p>
<ul class="trials">{trial}
<li class="trial"><h3>Enrollment update</h3><p>Participant 014, Gary Whitfield, 67, enrolled after a
stage III colon cancer diagnosis and began chemotherapy on April 2.</p></li></ul>""",
        description="Find a clinical trial at Mercy Valley Health."))
    plant("research/clinical-trials.html", "Gary Whitfield",
          "a named trial participant with his diagnosis on a public page")

    write("careers/registered-nurse-oncology.html", page(
        "Registered Nurse - Oncology Unit | Careers | Mercy Valley Health",
        """<article><h1>Registered Nurse &ndash; Oncology Unit</h1><p>Full time, nights.</p>
<p>Care for adults receiving chemotherapy and radiation for cancer. Chemotherapy and
biotherapy certification preferred.</p><p>Recruiter: Hannah Price, 555-0188,
careers@mercyvalley.example</p></article>""",
        head="""<script type="application/ld+json">{"@context":"https://schema.org","@type":"JobPosting",
"title":"Registered Nurse - Oncology Unit","hiringOrganization":{"@type":"Organization",
"name":"Mercy Valley Health"},"employmentType":"FULL_TIME"}</script>""",
        description="Join our oncology nursing team."))

    write("events/diabetes-support-group.html", page(
        "Diabetes Support Group | Events | Mercy Valley Health",
        """<h1>Diabetes support group</h1><p>Thursdays, 6 to 7 pm, Community Room B. Free.</p>
<p>Led by Maria Lopez, RN, CDCES, certified diabetes care and education specialist.</p>
<p>Questions? Call 555-0166.</p>
<p><a href="/events/diabetes-support-group-signups.csv">Download the sign-up sheet</a></p>""",
        head="""<script type="application/ld+json">{"@context":"https://schema.org","@type":"Event",
"name":"Diabetes support group","organizer":{"@type":"Person","name":"Maria Lopez"},
"location":{"@type":"Place","name":"Community Room B"}}</script>""",
        description="A free monthly support group for adults living with diabetes."))
    write("events/diabetes-support-group-signups.csv",
          "name,phone,condition,first_visit\nDorothy Sims,614-282-7710,type 2 diabetes,2025-02-06\n"
          "Raymond Cole,614-282-1932,type 1 diabetes,2025-02-13\n")
    for person in ("Dorothy Sims", "Raymond Cole"):
        plant("events/diabetes-support-group-signups.csv", person,
              "a sign-up sheet with names and conditions linked from a public page")

    write("insurance.html", page(
        "Insurance and Billing | Mercy Valley Health",
        """<h1>Insurance we accept</h1><ul><li>Medicare and Medicare Advantage</li><li>Ohio Medicaid</li>
<li>Anthem Blue Cross</li><li>UnitedHealthcare</li></ul>
<h2>Where to find your member ID</h2><figure class="sample-card"><img src="/assets/sample-card.png"
alt="Sample insurance card"><figcaption>Sample card. Member name: JOHN Q SAMPLE.
Member ID: XYZ123456789. Group number: 000123. Rx BIN: 004336.</figcaption></figure>
<p>Your member ID is on the front of your card, for example 123456789.</p>""",
        description="Insurance plans accepted at Mercy Valley Health."))

    write("developers/fhir.html", page(
        "FHIR API for Developers | Mercy Valley Health",
        """<h1>Patient Access API</h1><p>Our FHIR R4 API follows the HL7 specification. The example
below is the specification's own example patient.</p>
<pre><code>{
  "resourceType": "Patient",
  "id": "example",
  "identifier": [{"system": "urn:oid:1.2.36.146.595.217.0.1", "value": "12345"}],
  "name": [{"use": "official", "family": "Chalmers", "given": ["Peter", "James"]}],
  "gender": "male",
  "birthDate": "1974-12-25"
}</code></pre>
<p>Authorize with SMART on FHIR. Sandbox client id: demo-client-001.</p>""",
        description="Connect apps to Mercy Valley Health records with our FHIR API."))

    write("notice-of-privacy-practices.html", page(
        "Notice of Privacy Practices | Mercy Valley Health",
        """<h1>Notice of Privacy Practices</h1><p>This notice describes how medical information about
you may be used and disclosed and how you can get access to this information.</p>
<p>We may use your health information, such as your diagnosis, treatment and test results, to
treat you, to bill for your care and to run our hospitals.</p>
<p>Privacy Officer: Karen Doyle, 555-0110, privacy@mercyvalley.example</p>""",
        description="How Mercy Valley Health uses and protects your health information."))

    write("patient-stories/back-to-the-trail.html", page(
        "Back to the trail after knee replacement | Patient Stories | Mercy Valley Health",
        """<article><h1>Back to the trail</h1><p>Linda Osei, 61, had a total knee replacement in
January and was hiking again by May.</p><p class="note">Shared with Linda's written permission.</p></article>""",
        description="A patient's story of recovery after knee replacement."))

    write("patient-stories/beating-breast-cancer.html", page(
        "Rosa Delgado's breast cancer journey | Patient Stories | Mercy Valley Health",
        """<article><h1>Rosa's story</h1><p>Rosa Delgado was diagnosed with stage II breast cancer last
spring and finished radiation at our cancer center in October.</p></article>""",
        description="Rosa Delgado's breast cancer journey."))
    plant("patient-stories/beating-breast-cancer.html", "Rosa Delgado",
          "a patient story with a diagnosis and no consent marker")

    write("patient-portal/index.html", page(
        "MyChart | Mercy Valley Health",
        """<h1>MyChart</h1><p>Sign in to see test results, message your care team and pay bills.</p>
<script>window.__PORTAL_STATE__ = {"lastPatient": {"name": "Tomas Herrera",
"dob": "1958-07-14", "reason": "insulin dose review for type 2 diabetes"}};</script>""",
        description="Sign in to MyChart."))
    plant("patient-portal/index.html", "Tomas Herrera",
          "a patient's state embedded in the public sign-in page's script")

    write("api/appointments.json", json.dumps({"appointments": [
        {"patientName": "Helen Marsh", "mrn": "8823140", "provider": "Dr. Lena Fischer",
         "reason": "chemotherapy cycle 3", "time": "2025-04-02T09:30:00-04:00"}]}, indent=2))
    plant("api/appointments.json", "8823140", "an appointment feed with a patient's record number")

    write("wp-json/wp/v2/users.json", json.dumps([
        {"id": 3, "name": "Jordan Lee", "slug": "jlee", "description": "Communications manager",
         "link": "https://www.mercyvalley.example/author/jlee/"},
        {"id": 7, "name": "Daniel Cho", "slug": "dcho", "description": "Health writer",
         "link": "https://www.mercyvalley.example/author/dcho/"}], indent=2))

    urls = ["/", "/find-a-doctor/", "/health-library/type-2-diabetes.html",
            "/news/2025-cancer-center.html", "/research/clinical-trials.html",
            "/patient-stories/back-to-the-trail.html"]
    urls += [f"/find-a-doctor/cardiology/dr-{slug}.html" if specialty == "Cardiology"
             else f"/find-a-doctor/dr-{slug}.html" for slug, _, _, specialty, _, _ in DOCTORS]
    urls.append("/appointments/confirm?patient=Walter+Briggs&dx=C61")
    write("sitemap.xml", '<?xml version="1.0" encoding="UTF-8"?>\n'
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
          + "".join(f"  <url><loc>https://www.mercyvalley.example{u}</loc></url>\n" for u in urls)
          + "</urlset>\n")
    plant("sitemap.xml", "Walter Briggs", "an appointment link with a patient and a diagnosis code in the sitemap")

    write("robots.txt", "User-agent: *\nDisallow: /patient-portal/\nDisallow: /api/\n"
          "Sitemap: https://www.mercyvalley.example/sitemap.xml\n")
    write("assets/site.css", "body{font-family:'Source Sans Pro','Segoe UI',Roboto,Helvetica,Arial,"
          "sans-serif;color:#1f2937}.btn-primary{background-color:#283593}.badge-new::after{"
          "content:'New'}@media print{.site-header,.cookie-banner{display:none}a::after{"
          "content:' (' attr(href) ')'}}\n")
    write("assets/site.js", "document.querySelectorAll('.cookie-banner button').forEach(function(b){"
          "b.addEventListener('click',function(){b.closest('.cookie-banner').remove();});});\n")
    # Real library files, unmodified (fixtures/thirdparty/README.md).
    vendor = SITE / "assets" / "vendor"
    vendor.mkdir(parents=True, exist_ok=True)
    for source in sorted((ROOT.parent / "thirdparty").iterdir()):
        if not source.name.endswith((".LICENSE.txt", ".md")):
            shutil.copyfile(source, vendor / source.name)

    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "key.json").write_text(json.dumps({"leaks": KEY}, indent=2) + "\n", encoding="utf-8")
    print(f"built {sum(1 for p in SITE.rglob('*') if p.is_file())} files, {len(KEY)} planted leaks")


if __name__ == "__main__":
    build()
