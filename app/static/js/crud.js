
"use strict";

/* Generic CRUD table page. cfg: {
   endpoint, noun,
   columns: [{key,label,sortable,render(row)}],
   fields: [...],
   filters: [...],
   defaultSort,
   exportUrl,
   canEdit(row),
   canDelete(row),
   lockedFields(row),
   onRowClick
} */

function crudPage(cfg) {
  const isAdmin = document.body.dataset.role === "admin";

  const state = {
    sort: cfg.defaultSort[0],
    dir: cfg.defaultSort[1],
    editing: null,
    items: []
  };

  const $ = id => document.getElementById(id);

  const head = $("tableHead");
  const body = $("tableBody");
  const search = $("searchInput");
  const dlg = $("formDialog");
  const form = $("recordForm");

  const filterEls = {};

  // Normalize both string options and [value, label] options.
  function makeOption(option) {
    const [value, label] = Array.isArray(option)
      ? option
      : [option, option];

    return el("option", {
      value: value,
      text: label
    });
  }

  // Build filter dropdowns.
  cfg.filters.forEach(f => {
    const s = el(
      "select",
      { "aria-label": f.label },
      el("option", { value: "", text: f.label }),
      (f.options || []).map(makeOption)
    );

    s.addEventListener("change", load);

    filterEls[f.param] = s;
    $("filterBar").append(s);
  });

  // Configure export button.
  if (cfg.exportUrl) {
    $("exportBtn").href = cfg.exportUrl;
  } else {
    $("exportBtn").hidden = true;
  }

  // Render table headings.
  function renderHead() {
    head.replaceChildren(
      el(
        "tr",
        {},
        cfg.columns.map(c => {
          const key = c.sortKey || c.key;

          const arrow =
            state.sort === key
              ? (state.dir === "asc" ? " \u25B2" : " \u25BC")
              : "";

          const th = el("th", {
            class: c.sortable ? "sortable" : "",
            text: c.label + arrow
          });

          if (c.sortable) {
            th.addEventListener("click", () => {
              state.dir =
                state.sort === key && state.dir === "asc"
                  ? "desc"
                  : "asc";

              state.sort = key;

              renderHead();
              load();
            });
          }

          return th;
        }),
        isAdmin ? el("th", { text: "Actions" }) : null
      )
    );
  }

  // Render table rows.
  function renderRows() {
    $("emptyMsg").hidden = state.items.length > 0;

    body.replaceChildren(
      ...state.items.map(row =>
        el(
          "tr",
          {},
          cfg.columns.map(c => {
            const value = c.render
              ? c.render(row)
              : row[c.key];

            return el(
              "td",
              { class: c.cls || "" },
              value ?? "-"
            );
          }),

          isAdmin
            ? el(
                "td",
                { class: "actions" },

                el("button", {
                  class: "btn small",
                  type: "button",
                  text: "Edit",
                  onclick: () => openForm(row)
                }),

                " ",

                (cfg.canDelete ? cfg.canDelete(row) : true)
                  ? el("button", {
                      class: "btn small danger",
                      type: "button",
                      text: "Delete",
                      onclick: () => remove(row)
                    })
                  : null
              )
            : null
        )
      )
    );
  }

  // Load records from the API.
  async function load() {
    const p = new URLSearchParams({
      sort: state.sort,
      dir: state.dir
    });

    if (search.value.trim()) {
      p.set("q", search.value.trim());
    }

    for (const [key, select] of Object.entries(filterEls)) {
      if (select.value) {
        p.set(key, select.value);
      }
    }

    try {
      state.items = (
        await api(cfg.endpoint + "?" + p, {}, true)
      ).items;

      renderRows();
    } catch (e) {
      toast(e.message, true);
    }
  }

  // Build form fields.
  async function buildFields(row) {
    const wrap = $("formFields");

    wrap.replaceChildren();

    const locked =
      row && cfg.lockedFields
        ? cfg.lockedFields(row)
        : [];

    for (const f of cfg.fields) {
      let opts = f.options;
      
      // Load dropdown options from API when configured.
      if (f.optionsUrl) {
        const response = await api(f.optionsUrl, {}, true);

        opts = (response.items || []).map(o => [
          o.value,
          o.label
        ]);
      }

      let input;

      if (opts) {
        input = el(
          "select",
          {},
          el("option", {
            value: "",
            text: "Select..."
          }),
          opts.map(makeOption)
        );
      } else if (f.type === "textarea") {
        input = el("textarea", {
          rows: "3"
        });
      } else {
        input = el("input", {
          type: f.type || "text"
        });
      }

      input.id = "f_" + f.name;
      input.name = f.name;

      if (f.maxlength) {
        input.maxLength = f.maxlength;
      }

      if (f.min != null) {
        input.min = f.min;
        input.max = f.max;

        if (f.step) {
          input.step = f.step;
        }
      }

      input.value =
        row && row[f.name] != null
          ? row[f.name]
          : (f.default ?? "");

      if (locked.includes(f.name)) {
        input.disabled = true;
      }

      wrap.append(
        el("label", {
          for: input.id,
          text: f.label + (f.required ? " *" : "")
        }),
        input
      );

      if (f.hint) {
        wrap.append(
          el("div", {
            class: "field-hint",
            text: f.hint
          })
        );
      }
    }
  }

  // Open add/edit dialog.
  async function openForm(row) {
    state.editing = row || null;

    $("formError").hidden = true;

    $("formTitle").textContent =
      (row ? "Edit " : "Add ") + cfg.noun;

    try {
      await buildFields(row);
      dlg.showModal();
    } catch (e) {
      toast(e.message, true);
    }
  }

  // Validate form fields.
  function validate() {
    for (const f of cfg.fields) {
      const input = $("f_" + f.name);

      input.classList.remove("field-err");

      if (input.disabled) {
        continue;
      }

      const value = input.value.trim();

      let message = "";

      if (f.required && !value) {
        message = f.label + " is required";
      } else if (
        f.type === "number" &&
        value &&
        (
          isNaN(value) ||
          +value < f.min ||
          +value > f.max
        )
      ) {
        message =
          f.label +
          " must be between " +
          f.min +
          " and " +
          f.max;
      } else if (
        f.pattern &&
        value &&
        !f.pattern.test(value)
      ) {
        message =
          f.patternMsg ||
          f.label + " is invalid";
      }

      if (message) {
        input.classList.add("field-err");
        input.focus();

        return message;
      }
    }

    return "";
  }

  // Submit add/edit form.
  form.addEventListener("submit", async e => {
    e.preventDefault();

    const error = validate();

    if (error) {
      $("formError").textContent = error;
      $("formError").hidden = false;
      return;
    }

    const data = {};

    cfg.fields.forEach(f => {
      const input = $("f_" + f.name);

      if (!input.disabled) {
        data[f.name] = input.value.trim();
      }
    });

    try {
      if (state.editing) {
        await api(
          cfg.endpoint + "/" + state.editing.id,
          {
            method: "PUT",
            body: data
          }
        );
      } else {
        await api(
          cfg.endpoint,
          {
            method: "POST",
            body: data
          }
        );
      }

      dlg.close();

      toast(
        cfg.noun +
        (state.editing ? " updated" : " created")
      );

      load();

    } catch (ex) {
      $("formError").textContent = ex.message;
      $("formError").hidden = false;
    }
  });

  // Delete a record.
  async function remove(row) {
    const confirmed = await confirmDialog(
      "Delete " +
      cfg.noun.toLowerCase() +
      " " +
      (cfg.label ? cfg.label(row) : "#" + row.id) +
      "? This cannot be undone."
    );

    if (!confirmed) {
      return;
    }

    try {
      await api(
        cfg.endpoint + "/" + row.id,
        {
          method: "DELETE"
        }
      );

      toast(cfg.noun + " deleted");

      load();

    } catch (ex) {
      toast(ex.message, true);
    }
  }

  // Dialog buttons.
  $("cancelBtn").addEventListener("click", () => {
    dlg.close();
  });

  $("addBtn").addEventListener("click", () => {
    openForm(null);
  });

  if (!cfg.canAdd && cfg.canAdd !== undefined) {
    $("addBtn").hidden = true;
  }

  // Search records.
  search.addEventListener(
    "input",
    debounce(load, 250)
  );

  // Initial render and data load.
  renderHead();
  load();

  return {
    reload: load
  };
}
