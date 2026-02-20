function initClaimsEditor(
  editorId,
  rawId,
  hiddenInputId,
  toggleBtnId,
  initialClaims
) {
  const editor = document.getElementById(editorId);
  const rawTextarea = document.getElementById(rawId);
  const hiddenInput = document.getElementById(hiddenInputId);
  const toggleBtn = document.getElementById(toggleBtnId);

  let mode = "form"; // "form" or "json"

  function createRow(key, value) {
    const row = document.createElement("div");
    row.className = "claim-row";

    const keyInput = document.createElement("input");
    keyInput.type = "text";
    keyInput.className = "claim-key";
    keyInput.placeholder = "key";
    keyInput.value = key || "";

    const valueInput = document.createElement("input");
    valueInput.type = "text";
    valueInput.className = "claim-value";
    valueInput.placeholder = 'string, 42, true, ["a","b"], ...';
    valueInput.value = value !== undefined ? formatValue(value) : "";

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "claim-remove";
    removeBtn.textContent = "\u00d7";
    removeBtn.title = "Remove claim";
    removeBtn.addEventListener("click", function () {
      row.remove();
    });

    row.appendChild(keyInput);
    row.appendChild(valueInput);
    row.appendChild(removeBtn);
    editor.insertBefore(row, editor.querySelector(".claim-add-row"));
    return row;
  }

  function formatValue(val) {
    if (typeof val === "string") return val;
    return JSON.stringify(val);
  }

  function parseValue(str) {
    str = str.trim();
    if (str === "") return "";
    try {
      return JSON.parse(str);
    } catch {
      return str;
    }
  }

  function collectClaims() {
    const claims = {};
    editor.querySelectorAll(".claim-row").forEach(function (row) {
      const key = row.querySelector(".claim-key").value.trim();
      const val = row.querySelector(".claim-value").value;
      if (key) {
        claims[key] = parseValue(val);
      }
    });
    return claims;
  }

  function populateRows(claims) {
    editor.querySelectorAll(".claim-row").forEach(function (row) {
      row.remove();
    });
    if (claims && typeof claims === "object" && !Array.isArray(claims)) {
      for (const [key, value] of Object.entries(claims)) {
        createRow(key, value);
      }
    }
  }

  function switchToForm() {
    // Parse raw JSON and populate rows
    let claims = {};
    try {
      claims = JSON.parse(rawTextarea.value);
    } catch {
      // leave rows as-is if JSON is invalid
    }
    populateRows(claims);
    rawTextarea.style.display = "none";
    editor.style.display = "";
    toggleBtn.textContent = "JSON";
    mode = "form";
  }

  function switchToJson() {
    // Serialize rows into the textarea
    const claims = collectClaims();
    rawTextarea.value = JSON.stringify(claims, null, 2);
    editor.style.display = "none";
    rawTextarea.style.display = "";
    toggleBtn.textContent = "Form";
    mode = "json";
  }

  toggleBtn.addEventListener("click", function () {
    if (mode === "form") {
      switchToJson();
    } else {
      switchToForm();
    }
  });

  // Add button row
  const addRow = document.createElement("div");
  addRow.className = "claim-add-row";
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.className = "claim-add";
  addBtn.textContent = "+ Add Claim";
  addBtn.addEventListener("click", function () {
    createRow("", "");
  });
  addRow.appendChild(addBtn);
  editor.appendChild(addRow);

  // Populate from initial claims
  if (initialClaims && typeof initialClaims === "object") {
    for (const [key, value] of Object.entries(initialClaims)) {
      createRow(key, value);
    }
  }
  rawTextarea.value = JSON.stringify(initialClaims || {}, null, 2);

  // Serialize claims into hidden input on form submit
  hiddenInput.form.addEventListener("submit", function () {
    if (mode === "form") {
      hiddenInput.value = JSON.stringify(collectClaims());
    } else {
      hiddenInput.value = rawTextarea.value;
    }
  });
}
