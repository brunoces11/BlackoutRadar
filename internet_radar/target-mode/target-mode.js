(function installTargetMode() {
  if (window.__targetModeInstalled) return;
  window.__targetModeInstalled = true;

  var enabled = false;
  var layer = null;
  var hoverBox = null;
  var hoverLabel = null;
  var badge = null;
  var hoverTarget = null;
  var suppressClickUntil = 0;
  var selectedItems = [];
  var selectedElements = [];
  var selectedBoxes = [];

  var TARGET_MODE_ROOT_ATTR = "data-target-mode-root";
  var TARGET_MODE_IGNORE_ATTR = "data-target-mode-ignore";
  var TARGET_MODE_SCOPE_ATTR = "data-target-mode-scope";
  var DATA_INSPECT_PATH = "data-inspect-path";
  var DATA_INSPECT_LABEL = "data-inspect-label";
  var DATA_INSPECT_ELEMENT = "data-inspect-element";
  var DATA_INSPECT_DESCRIPTION = "data-inspect-description";
  var DATA_INSPECT_ASSOCIATED_TEXT = "data-inspect-associated-text";
  var MIN_USEFUL_RECT_SIZE = 4;
  var MAX_LABEL_WIDTH = 320;
  var INTERACTIVE_SELECTOR = [
    "button",
    "a[href]",
    "input",
    "textarea",
    "select",
    "summary",
    '[role="button"]',
    '[role="link"]',
    '[role="menuitem"]',
    '[role="option"]',
    '[tabindex]:not([tabindex="-1"])',
  ].join(",");
  var SVG_INTERNAL_TAGS = {
    circle: true,
    clippath: true,
    defs: true,
    ellipse: true,
    g: true,
    line: true,
    mask: true,
    path: true,
    polygon: true,
    polyline: true,
    rect: true,
    symbol: true,
    text: true,
    use: true,
  };

  function normalizeText(value) {
    return (value || "").replace(/\s+/g, " ").trim();
  }

  function getActiveDomLanguage() {
    return normalizeText(document.documentElement.lang);
  }

  function withLanguageContext(targetPath, activeLanguage) {
    if (!activeLanguage) return targetPath;

    var languageSegment = "language:'" + activeLanguage + "'";

    if (targetPath === languageSegment || targetPath.indexOf(languageSegment + " > ") === 0) {
      return targetPath;
    }

    return languageSegment + " > " + targetPath;
  }

  function quoteClipboardValue(value) {
    return value.replace(/"/g, "'");
  }

  function slugifyLabel(value) {
    return normalizeText(value)
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 72);
  }

  function getDomTarget(element) {
    return element.tagName.toLowerCase();
  }

  function normalizeTarget(node) {
    if (!node) return null;
    if (node.closest("[" + TARGET_MODE_IGNORE_ATTR + "]")) return null;
    return getPrimaryInspectTarget(node);
  }

  function getPointTarget(clientX, clientY) {
    return normalizeTarget(document.elementFromPoint(clientX, clientY));
  }

  function getEventTarget(target) {
    if (target instanceof Element) return normalizeTarget(target);
    if (target instanceof Text && target.parentElement) return normalizeTarget(target.parentElement);
    return null;
  }

  function getPrimaryInspectTarget(element) {
    var tag = getDomTarget(element);
    var svgElement = tag === "svg" ? element : element.closest("svg");
    var isSvgInternalNode = SVG_INTERNAL_TAGS[tag] && !!svgElement;

    if (!isSvgInternalNode && tag !== "svg") return element;

    var interactiveAncestor = element.closest(INTERACTIVE_SELECTOR);
    if (interactiveAncestor && svgElement && interactiveAncestor.contains(svgElement)) {
      return interactiveAncestor;
    }

    return svgElement || element;
  }

  function getClosestAttribute(element, attribute) {
    var closest = element.closest("[" + attribute + "]");
    return closest ? closest.getAttribute(attribute) || "" : "";
  }

  function getClosestOptionalAttribute(element, attribute) {
    return normalizeText(getClosestAttribute(element, attribute));
  }

  function getClosestAttributeFromList(element, attributes) {
    for (var index = 0; index < attributes.length; index += 1) {
      var value = getClosestOptionalAttribute(element, attributes[index]);
      if (value) return value;
    }

    return "";
  }

  function getUsefulBoxElement(element) {
    var current = element;

    while (current && current !== document.documentElement) {
      var rect = current.getBoundingClientRect();
      if (rect.width >= MIN_USEFUL_RECT_SIZE && rect.height >= MIN_USEFUL_RECT_SIZE) {
        return current;
      }

      current = current.parentElement;
    }

    return element;
  }

  function getReadableText(element) {
    var text = normalizeText(element.textContent);
    if (!text || text.length > 64) return "";
    if (text.split(" ").length > 8) return "";
    return text;
  }

  function getVisibleText(element) {
    var text = normalizeText(element.textContent);
    if (!text) return "";
    return text.length > 140 ? text.slice(0, 137) + "..." : text;
  }

  function getElementLabel(element) {
    var inputElement = element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement ? element : null;
    var imageElement = element instanceof HTMLImageElement ? element : null;
    var label =
      element.getAttribute(DATA_INSPECT_LABEL) ||
      element.getAttribute("aria-label") ||
      element.getAttribute("data-tooltip") ||
      element.getAttribute("title") ||
      (imageElement ? imageElement.alt : "") ||
      (inputElement ? inputElement.placeholder : "") ||
      (inputElement ? inputElement.name : "") ||
      getReadableText(element);

    return normalizeText(label);
  }

  var STABLE_ID_ATTRIBUTES = ["data-target-mode-id", DATA_INSPECT_ELEMENT, "data-testid", "data-test-id", "data-cy", "id", "data-dev-element-id", "data-dev-element"];

  function getExplicitIdentity(element) {
    for (var index = 0; index < STABLE_ID_ATTRIBUTES.length; index += 1) {
      var attribute = STABLE_ID_ATTRIBUTES[index];
      var value = normalizeText(attribute === "id" ? element.id : element.getAttribute(attribute));
      if (value) return { attribute: attribute, value: value };
    }
    return null;
  }

  function getExplicitElementId(element) {
    var identity = getExplicitIdentity(element);
    return slugifyLabel(identity ? identity.value : "");
  }

  function getElementKind(element) {
    var tag = getDomTarget(element);
    var role = element.getAttribute("role");

    if (tag === "button" || role === "button") return "button";
    if (tag === "a" || role === "link") return "link";
    if (tag === "input") return "input";
    if (tag === "textarea") return "textarea";
    if (tag === "select") return "select";
    if (tag === "img") return "image";
    if (tag === "svg" || tag === "path" || tag === "p-icon") return "icon";
    if (tag === "td" || tag === "th") return "cell";
    if (tag === "tr") return "row";
    if (/^h[1-6]$/.test(tag)) return "heading";
    if (tag === "label" || tag === "span") return "label";
    return "";
  }

  function withElementKind(label, element) {
    var slug = slugifyLabel(label);
    var kind = getElementKind(element);

    if (!slug) return "";
    if (!kind || slug.slice(-kind.length - 1) === "-" + kind || slug === kind) return slug;

    return slug + "-" + kind;
  }

  function getSemanticScope(element) {
    return element.closest("[" + TARGET_MODE_SCOPE_ATTR + '], [data-dev-inspectable="true"]');
  }

  function getOwnerScope(element) {
    return element.closest("[" + TARGET_MODE_SCOPE_ATTR + "], [data-target-mode-component], [" + DATA_INSPECT_PATH + "], [data-target-mode-section], [data-target-mode-page], [data-dev-inspectable=\"true\"]") || document.body;
  }

  function getScopeName(scope) {
    return normalizeText(scope.getAttribute(TARGET_MODE_SCOPE_ATTR) || scope.getAttribute("data-target-mode-component") || scope.getAttribute(DATA_INSPECT_PATH) || scope.getAttribute("data-target-mode-section") || scope.getAttribute("data-target-mode-page") || getElementName(scope));
  }

  function isUniqueIdentity(identity, scope) {
    var matches = [scope].concat(Array.from(scope.querySelectorAll("[" + identity.attribute + "]"))).filter(function (entry) {
      return normalizeText(identity.attribute === "id" ? entry.id : entry.getAttribute(identity.attribute)) === identity.value;
    });
    return matches.length === 1;
  }

  function getStableClasses(element) {
    var className = typeof element.className === "string" ? element.className : element.getAttribute("class") || "";
    return className.split(/\s+/).filter(function (part) {
      return part && !/^(active|selected|disabled|loading|open|closed)$/i.test(part) && !/^(css|sc)-[\w-]+$/i.test(part);
    }).slice(0, 2);
  }

  function getEquivalenceSignature(element) {
    return [getDomTarget(element), normalizeText(element.getAttribute("role")), getElementKind(element), getExplicitElementId(element), getStableClasses(element).join("."), slugifyLabel(getElementLabel(element))].join("|");
  }

  function getEquivalentElements(element, scope) {
    var signature = getEquivalenceSignature(element);
    return Array.from(scope.querySelectorAll("*")).filter(function (entry) {
      return getPrimaryInspectTarget(entry) === entry && getEquivalenceSignature(entry) === signature;
    });
  }

  function getLocatorSegment(element) {
    var identity = getExplicitIdentity(element);
    if (identity && isUniqueIdentity(identity, document)) return identity.attribute === "id" ? "#" + identity.value : "[" + identity.attribute + '=\"' + identity.value.replace(/\"/g, "\\\"") + '\"]';
    var base = getDomTarget(element) + getStableClasses(element).map(function (part) { return "." + part; }).join("");
    var siblings = element.parentElement ? Array.from(element.parentElement.children).filter(function (entry) { return getDomTarget(entry) === getDomTarget(element); }) : [];
    return siblings.length > 1 ? base + ":nth-of-type(" + (siblings.indexOf(element) + 1) + ")" : base;
  }

  function getStructuralLocator(element, scope) {
    var segments = [], current = element;
    while (current && current !== scope && current !== document.body) { segments.unshift(getLocatorSegment(current)); current = current.parentElement; }
    return segments.join(" > ");
  }

  function shortFingerprint(value) {
    var hash = 2166136261;
    for (var index = 0; index < value.length; index += 1) hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
    return (hash >>> 0).toString(16).slice(0, 6);
  }

  function getSemanticElementId(target) {
    var semanticScope = getSemanticScope(target);
    var current = target;

    while (current && current !== document.documentElement) {
      var explicitElementId = getExplicitElementId(current);
      if (explicitElementId) return explicitElementId;

      var label = getElementLabel(current);
      var labeledElementId = withElementKind(label, current);
      if (labeledElementId) return labeledElementId;

      if (current === semanticScope) break;
      current = current.parentElement;
    }

    return getDomTarget(target);
  }

  function getTargetPathSegment(target) {
    var kind = getElementKind(target);
    var elementId = getSemanticElementId(target);
    var finalTarget = kind ? kind + ":" + elementId : elementId;

    return "final-target:'" + finalTarget + "'";
  }

  function getStructuredTargetPath(target) {
    var page = getClosestAttributeFromList(target, ["data-target-mode-page", "data-dev-page"]);
    var section = getClosestAttributeFromList(target, ["data-target-mode-section", "data-dev-section"]);
    var component = getClosestAttributeFromList(target, ["data-target-mode-component", "data-dev-component"]);

    if (!page && !section && !component) return "";

    return [
      page ? "page:" + page : "",
      section ? "section:" + section : "",
      component ? "component:" + component : "",
      getTargetPathSegment(target),
    ].filter(Boolean).join(" > ");
  }

  function getElementName(element) {
    var label = getElementLabel(element);
    if (label) return label;

    if (element.id) return "#" + element.id;

    var testId =
      element.getAttribute("data-testid") ||
      element.getAttribute("data-test-id") ||
      element.getAttribute("data-cy");
    if (testId) return "[" + testId + "]";

    var className = typeof element.className === "string" ? element.className : element.getAttribute("class") || "";
    var usefulClass = className.split(/\s+/).find(function (part) {
      return part && !/^(active|selected|disabled|loading|open|closed)$/i.test(part);
    });

    return usefulClass ? getDomTarget(element) + "." + usefulClass : getDomTarget(element);
  }

  function getTargetPath(element, activeLanguage) {
    activeLanguage = activeLanguage === undefined ? getActiveDomLanguage() : activeLanguage;
    var explicitPath = normalizeText(element.getAttribute(DATA_INSPECT_PATH) || getClosestAttribute(element, DATA_INSPECT_PATH));
    if (explicitPath) return withLanguageContext(explicitPath, activeLanguage);

    var structuredPath = getStructuredTargetPath(element);
    if (structuredPath) return withLanguageContext(structuredPath, activeLanguage);

    var segments = [];
    var current = element.parentElement;

    while (current && current !== document.body && current !== document.documentElement) {
      if (current.hasAttribute(TARGET_MODE_ROOT_ATTR) || current.hasAttribute(TARGET_MODE_IGNORE_ATTR)) break;

      segments.unshift(getElementName(current));
      if (current.hasAttribute(TARGET_MODE_SCOPE_ATTR)) break;

      current = current.parentElement;
    }

    return withLanguageContext(segments.concat([getTargetPathSegment(element)]).filter(Boolean).join(" > "), activeLanguage);
  }

  function getAssociatedVisibleText(target) {
    var explicitText = getClosestOptionalAttribute(target, DATA_INSPECT_ASSOCIATED_TEXT);
    if (explicitText) return explicitText;

    var ownText = getReadableText(target);
    if (ownText) return ownText;

    var semanticScope = getSemanticScope(target);
    var current = target.parentElement;

    while (current && current !== semanticScope && current !== document.body) {
      var text = getVisibleText(current);
      if (text && text.length <= 140) return text;
      current = current.parentElement;
    }

    return "";
  }

  function getSemanticDescription(target) {
    var explicitDescription = getClosestOptionalAttribute(target, DATA_INSPECT_DESCRIPTION);
    if (explicitDescription) return explicitDescription;

    var label = getElementLabel(target);
    var associatedText = getAssociatedVisibleText(target);
    if (!label || label === associatedText) return "";

    return label;
  }

  function getTechnicalElement(element) {
    var parts = [getDomTarget(element)];
    var testId =
      element.getAttribute("data-testid") ||
      element.getAttribute("data-test-id") ||
      element.getAttribute("data-cy");
    var role = element.getAttribute("role");
    var className = typeof element.className === "string" ? element.className : element.getAttribute("class") || "";

    if (element.id) parts.push("#" + element.id);
    if (testId) parts.push('[data-testid="' + testId + '"]');
    if (role) parts.push('[role="' + role + '"]');
    className.split(/\s+/).filter(Boolean).slice(0, 3).forEach(function (part) {
      parts.push("." + part);
    });

    return parts.join("");
  }

  function getOverlayLabel(element) {
    return getSemanticElementId(element) + " | " + getDomTarget(element);
  }

  function createItem(element) {
    var activeLanguage = getActiveDomLanguage();
    var visibleText = getAssociatedVisibleText(element);
    var semanticDescription = getSemanticDescription(element);
    var scope = getOwnerScope(element);
    var scopeName = getScopeName(scope);
    var identity = getExplicitIdentity(element);
    var uniqueIdentity = identity && isUniqueIdentity(identity, scope);
    var equivalents = getEquivalentElements(element, scope);
    var instanceIndex = equivalents.indexOf(element);
    var instance = equivalents.length > 1 && instanceIndex >= 0 ? (instanceIndex + 1) + "/" + equivalents.length : "";
    var locator = uniqueIdentity ? "" : getStructuralLocator(element, scope);
    var fingerprint = uniqueIdentity ? "" : shortFingerprint(scopeName + ">" + locator);
    var item = {
      targetPath: getTargetPath(element, activeLanguage),
      technicalElement: getTechnicalElement(element),
    };

    if (activeLanguage) item.activeLanguage = activeLanguage;
    if (visibleText) item.visibleText = visibleText;
    if (semanticDescription) item.semanticDescription = semanticDescription;
    if (uniqueIdentity) item.uid = identity.value;
    if (scopeName) item.scope = scopeName;
    if (instance) item.instance = instance;
    if (locator) item.locator = locator;
    if (fingerprint) item.fingerprint = fingerprint;

    return item;
  }

  function createBox(element) {
    var visualElement = getUsefulBoxElement(element);
    var rect = visualElement.getBoundingClientRect();

    if (rect.width < MIN_USEFUL_RECT_SIZE || rect.height < MIN_USEFUL_RECT_SIZE) return null;

    var labelTop = rect.top > 31 ? rect.top - 29 : rect.bottom + 7;
    var labelLeft = Math.min(Math.max(rect.left, 8), Math.max(8, window.innerWidth - MAX_LABEL_WIDTH - 8));

    return {
      key: getStructuralLocator(element, getOwnerScope(element)) || getTargetPath(element),
      top: rect.top,
      left: rect.left,
      width: rect.width,
      height: rect.height,
      labelTop: labelTop,
      labelLeft: labelLeft,
      label: getOverlayLabel(element),
    };
  }

  function formatSingle(item, index) {
    function field(name, value) { return name + ':"' + quoteClipboardValue(value) + '"'; }
    var fields = ["i:" + index];
    if (item.activeLanguage) fields.push(field("lang", item.activeLanguage));
    fields.push(field("path", item.targetPath), field("node", item.technicalElement));
    if (item.visibleText) fields.push(field("text", item.visibleText));
    if (item.semanticDescription) fields.push(field("description", item.semanticDescription));
    if (item.uid) fields.push(field("uid", item.uid));
    if (item.scope) fields.push(field("scope", item.scope));
    if (item.instance) fields.push("instance:" + item.instance);
    if (item.locator) fields.push(field("locator", item.locator));
    if (item.fingerprint) fields.push(field("fingerprint", item.fingerprint));
    fields.push('rule:"edit only this exact target"');
    return "{" + fields.join("; ") + ";}";
  }

  function formatClipboard(items) {
    return items.length === 1 ? formatSingle(items[0], 1) : "Targets[\n" + items.map(function (item, index) { return formatSingle(item, index + 1); }).join("\n") + "\n]";
  }

  function copyTargets(items) {
    var text = formatClipboard(items);

    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () {
        return copyTargetsFallback(text);
      });
    }

    return copyTargetsFallback(text);
  }

  function copyTargetsFallback(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
    return Promise.resolve();
  }

  function removeSelectedBoxNodes() {
    if (!layer) return;
    layer.querySelectorAll(".target-mode-selected-box, .target-mode-selected-label").forEach(function (node) {
      node.remove();
    });
  }

  function renderBoxes() {
    if (!layer) return;

    removeSelectedBoxNodes();
    selectedBoxes.forEach(function (box) {
      var boxNode = document.createElement("div");
      boxNode.className = "target-mode-selected-box";
      boxNode.style.top = box.top + "px";
      boxNode.style.left = box.left + "px";
      boxNode.style.width = box.width + "px";
      boxNode.style.height = box.height + "px";

      var labelNode = document.createElement("div");
      labelNode.className = "target-mode-selected-label";
      labelNode.style.top = box.labelTop + "px";
      labelNode.style.left = box.labelLeft + "px";
      labelNode.textContent = box.label;

      layer.insertBefore(boxNode, hoverBox);
      layer.insertBefore(labelNode, hoverBox);
    });
  }

  function refreshSelectedBoxes() {
    selectedElements = selectedElements.filter(function (element) {
      return document.contains(element);
    });
    selectedBoxes = selectedElements.map(createBox).filter(Boolean);
    renderBoxes();
    return selectedBoxes;
  }

  function setBadge(text) {
    if (badge) badge.textContent = text;
  }

  function hideHoverBox() {
    if (hoverBox) hoverBox.style.display = "none";
    if (hoverLabel) hoverLabel.style.display = "none";
  }

  function isSelectedBox(box) {
    return selectedBoxes.some(function (selectedBox) {
      return selectedBox.key === box.key;
    });
  }

  function updateHoverFromTarget(target) {
    hoverTarget = target;

    if (!target || !hoverBox || !hoverLabel) {
      hideHoverBox();
      return;
    }

    var box = createBox(target);
    if (!box || isSelectedBox(box)) {
      hideHoverBox();
      return;
    }

    hoverBox.style.display = "block";
    hoverBox.style.top = box.top + "px";
    hoverBox.style.left = box.left + "px";
    hoverBox.style.width = box.width + "px";
    hoverBox.style.height = box.height + "px";

    hoverLabel.style.display = "block";
    hoverLabel.style.top = box.labelTop + "px";
    hoverLabel.style.left = box.labelLeft + "px";
    hoverLabel.textContent = box.label;
  }

  function stopTargetModeEvent(event, preventDefault) {
    if (preventDefault !== false) event.preventDefault();
    event.stopPropagation();
    if (event.stopImmediatePropagation) event.stopImmediatePropagation();
  }

  function inspectTarget(target, appendSelection) {
    if (!target || target === document.documentElement || target === document.body) return;

    var targetBox = createBox(target);
    if (!targetBox) return;

    if (appendSelection) {
      selectedElements = selectedElements.filter(function (entry) {
        var entryBox = createBox(entry);
        return entryBox && entryBox.key !== targetBox.key;
      }).concat(target);
    } else {
      selectedElements = [target];
    }

    refreshSelectedBoxes();
    selectedItems = selectedElements.map(createItem);
    updateHoverFromTarget(target);

    copyTargets(selectedItems)
      .then(function () {
        setBadge("Copied " + selectedItems.length + " target" + (selectedItems.length === 1 ? "" : "s"));
      })
      .catch(function () {
        setBadge("Copy failed");
      });
  }

  function enable() {
    enabled = true;
    selectedItems = [];
    selectedElements = [];
    selectedBoxes = [];
    hoverTarget = null;
    document.body.classList.add("target-mode-enabled");

    layer = document.createElement("div");
    layer.className = "target-mode-layer";
    layer.setAttribute(TARGET_MODE_ROOT_ATTR, "");
    layer.setAttribute(TARGET_MODE_IGNORE_ATTR, "");

    hoverBox = document.createElement("div");
    hoverBox.className = "target-mode-box";
    hoverBox.style.display = "none";

    hoverLabel = document.createElement("div");
    hoverLabel.className = "target-mode-label";
    hoverLabel.style.display = "none";

    badge = document.createElement("div");
    badge.className = "target-mode-badge";
    badge.textContent = "Target mode active";

    layer.appendChild(hoverBox);
    layer.appendChild(hoverLabel);
    layer.appendChild(badge);
    document.body.appendChild(layer);

    window.addEventListener("pointermove", onPointerMove, true);
    window.addEventListener("pointerdown", onPointerDown, true);
    window.addEventListener("mousedown", onBlockedMouseEvent, true);
    window.addEventListener("mouseup", onBlockedMouseEvent, true);
    window.addEventListener("click", onClick, true);
    window.addEventListener("dblclick", onBlockedMouseEvent, true);
    window.addEventListener("auxclick", onBlockedMouseEvent, true);
    window.addEventListener("contextmenu", onBlockedMouseEvent, true);
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize, true);
  }

  function disable() {
    enabled = false;
    selectedItems = [];
    selectedElements = [];
    selectedBoxes = [];
    hoverTarget = null;
    document.body.classList.remove("target-mode-enabled");
    window.removeEventListener("pointermove", onPointerMove, true);
    window.removeEventListener("pointerdown", onPointerDown, true);
    window.removeEventListener("mousedown", onBlockedMouseEvent, true);
    window.removeEventListener("mouseup", onBlockedMouseEvent, true);
    window.removeEventListener("click", onClick, true);
    window.removeEventListener("dblclick", onBlockedMouseEvent, true);
    window.removeEventListener("auxclick", onBlockedMouseEvent, true);
    window.removeEventListener("contextmenu", onBlockedMouseEvent, true);
    window.removeEventListener("scroll", onScrollOrResize, true);
    window.removeEventListener("resize", onScrollOrResize, true);
    if (layer) layer.remove();
    layer = null;
    hoverBox = null;
    hoverLabel = null;
    badge = null;
  }

  function onPointerMove(event) {
    updateHoverFromTarget(getPointTarget(event.clientX, event.clientY));
  }

  function onPointerDown(event) {
    if (event.button !== 0) return;

    stopTargetModeEvent(event);
    suppressClickUntil = performance.now() + 650;
    inspectTarget(getPointTarget(event.clientX, event.clientY) || getEventTarget(event.target), event.ctrlKey || event.metaKey);
  }

  function onBlockedMouseEvent(event) {
    stopTargetModeEvent(event);
  }

  function onClick(event) {
    stopTargetModeEvent(event);

    if (performance.now() < suppressClickUntil) return;
    inspectTarget(getPointTarget(event.clientX, event.clientY) || getEventTarget(event.target), event.ctrlKey || event.metaKey);
  }

  function onScrollOrResize() {
    updateHoverFromTarget(hoverTarget);
    refreshSelectedBoxes();
  }

  window.addEventListener("keydown", function (event) {
    if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "h" && !event.repeat) {
      event.preventDefault();
      if (enabled) disable();
      else enable();
    }
  });
})();
