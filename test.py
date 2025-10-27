import xml.etree.ElementTree as ET
import pandas as pd

# XML data
xml_data = """
<steps id="0" last="7">
    <step id="2" type="ValidateStep">
        <parameterizedString isformatted="true">GIVEN: Provider type = MC03</parameterizedString>
        <parameterizedString isformatted="true">Verified
        </parameterizedString>
        <description/>
    </step>
    <step id="3" type="ValidateStep">
        <parameterizedString isformatted="true">AND: Billing NPI = 1861256588</parameterizedString>
        <parameterizedString isformatted="true">Verified</parameterizedString>
        <description/>
    </step>
    <step id="4" type="ValidateStep">
        <parameterizedString isformatted="true">AND: HCPCS = T1041</parameterizedString>
        <parameterizedString isformatted="true">Verified</parameterizedString>
        <description/>
    </step>
    <step id="5" type="ValidateStep">
        <parameterizedString isformatted="true">WHEN: Billing NPI is active in MCAID_RI_CCBHC_PROV_NPI table</parameterizedString>
        <parameterizedString isformatted="true">Verified</parameterizedString>
        <description/>
    </step>
    <step id="6" type="ValidateStep">
        <parameterizedString isformatted="true">AND: No history claim found</parameterizedString>
        <parameterizedString isformatted="true">Verified</parameterizedString>
        <description/>
    </step>
    <step id="7" type="ValidateStep">
        <parameterizedString isformatted="true">THEN: Edit E005150 is not triggering at header level.</parameterizedString>
        <parameterizedString isformatted="true">Edit E005150 should not trigger at header level</parameterizedString>
        <description/>
    </step>
</steps>
"""

# Parse XML
root = ET.fromstring(xml_data)

data = []
step_counter = 1

for step in root.findall("step"):
    # Get all <parameterizedString> texts
    param_texts = [p.text.strip() if p.text else "" for p in step.findall("parameterizedString")]
    
    # Combine action + step text into one string
    action_combined = ""
    if param_texts:
        first_text = param_texts[0]
        if ":" in first_text:
            action, step_text = first_text.split(":", 1)
            action_combined = f"{action.strip()}: {step_text.strip()}"
        else:
            action_combined = first_text.strip()
    
    # Validation text (usually second parameterizedString)
    validate = param_texts[1] if len(param_texts) > 1 else ""
    
    # Description (optional)
    description = step.find("description").text.strip() if step.find("description") is not None and step.find("description").text else ""
    
    data.append({
        "Step": step_counter,
        "Action": action_combined,
        "Validate": validate,
        "Description": description
    })
    
    step_counter += 1

# Create DataFrame
df = pd.DataFrame(data)

# Display
print(df)

# Save to Excel without index
df.to_excel("steps_combined.xlsx", index=False)
