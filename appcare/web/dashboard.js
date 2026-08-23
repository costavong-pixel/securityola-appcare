(() => {
  "use strict";

  const loadingState = document.querySelector("#loading-state");
  const errorState = document.querySelector("#error-state");
  const emptyState = document.querySelector("#empty-state");
  const dashboardContent = document.querySelector("#dashboard-content");
  const errorMessage = document.querySelector("#error-message");
  const refreshButton = document.querySelector("#refresh-button");
  const retryButton = document.querySelector("#retry-button");

  const elements = {
    tenantName: document.querySelector("#tenant-name"),
    statusBanner: document.querySelector(".status-banner"),
    statusTitle: document.querySelector("#status-title"),
    statusDetail: document.querySelector("#status-detail"),
    applicationCount: document.querySelector("#application-count"),
    openFindingCount: document.querySelector("#open-finding-count"),
    findingDetail: document.querySelector("#finding-detail"),
    capturedAt: document.querySelector("#captured-at"),
    portfolioCount: document.querySelector("#portfolio-count"),
    applicationList: document.querySelector("#application-list"),
    signalList: document.querySelector("#signal-list"),
    activityList: document.querySelector("#activity-list"),
  };

  function text(value, fallback = "—") {
    return typeof value === "string" && value.length > 0 ? value : fallback;
  }

  function formatDate(value) {
    if (!value) return "Not recorded";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Not recorded" : date.toLocaleString();
  }

  function setMode(mode) {
    loadingState.hidden = mode !== "loading";
    errorState.hidden = mode !== "error";
    emptyState.hidden = mode !== "empty";
    dashboardContent.hidden = mode !== "content";
  }

  function clearChildren(element) {
    while (element.firstChild) element.removeChild(element.firstChild);
  }

  function badge(status) {
    const span = document.createElement("span");
    span.className = "status-badge status-badge-" + text(status, "unknown");
    span.textContent = text(status, "unknown");
    return span;
  }

  function renderApplicationList(applications) {
    clearChildren(elements.applicationList);
    applications.forEach((application) => {
      const item = document.createElement("article");
      item.className = "application-row";

      const copy = document.createElement("div");
      const title = document.createElement("h3");
      title.textContent = text(application.name, "Unnamed application");
      const detail = document.createElement("p");
      detail.textContent = application.environment + " · " + application.status;
      copy.append(title, detail);

      const findings = document.createElement("div");
      findings.className = "application-findings";
      const findingCount = document.createElement("strong");
      findingCount.textContent = String(application.open_finding_count);
      const findingLabel = document.createElement("span");
      findingLabel.textContent = "open findings";
      findings.append(findingCount, findingLabel);

      item.append(copy, findings, badge(application.open_finding_count > 0 ? "attention" : "healthy"));
      elements.applicationList.append(item);
    });
  }

  function renderSignals(snapshot) {
    clearChildren(elements.signalList);
    [
      ["Backup evidence", snapshot.backup],
      ["Connector health", snapshot.connectors],
      ["Deployment record", snapshot.deployments],
      ["Monitoring observations", snapshot.monitoring],
    ].forEach(([title, signal]) => {
      const item = document.createElement("article");
      item.className = "signal-row";

      const copy = document.createElement("div");
      const heading = document.createElement("h3");
      heading.textContent = title;
      const detail = document.createElement("p");
      detail.textContent = text(signal.detail, "No detail recorded.");
      copy.append(heading, detail);

      const meta = document.createElement("div");
      meta.className = "signal-meta";
      meta.append(badge(signal.status));
      const time = document.createElement("small");
      time.textContent = signal.last_event_at ? formatDate(signal.last_event_at) : "No timestamp";
      meta.append(time);

      item.append(copy, meta);
      elements.signalList.append(item);
    });
  }

  function renderActivity(activity) {
    clearChildren(elements.activityList);
    if (!activity.length) {
      const empty = document.createElement("p");
      empty.className = "inline-empty";
      empty.textContent = "No audit activity is recorded yet.";
      elements.activityList.append(empty);
      return;
    }
    activity.forEach((event) => {
      const item = document.createElement("div");
      item.className = "activity-row";
      const action = document.createElement("strong");
      action.textContent = text(event.action, "Recorded action");
      const detail = document.createElement("span");
      detail.textContent = event.subject_type + " · " + event.outcome;
      const time = document.createElement("time");
      time.dateTime = event.occurred_at;
      time.textContent = formatDate(event.occurred_at);
      item.append(action, detail, time);
      elements.activityList.append(item);
    });
  }

  function render(snapshot) {
    if (!snapshot || snapshot.state_source !== "backend") {
      throw new Error("The dashboard received no verified backend state.");
    }

    elements.tenantName.textContent = text(snapshot.tenant_name, "AppCare workspace");
    elements.statusTitle.textContent = text(snapshot.overall_status, "unknown");
    elements.statusDetail.textContent =
      snapshot.production && snapshot.production.enabled === false
        ? "Production actions are locked while the required live Preview evidence is absent."
        : "This status is derived from persisted AppCare records.";
    elements.statusBanner.dataset.status = text(snapshot.overall_status, "unknown");
    elements.applicationCount.textContent = String(snapshot.application_count);
    elements.openFindingCount.textContent = String(snapshot.findings.open);
    elements.findingDetail.textContent =
      snapshot.findings.critical + " critical · " + snapshot.findings.high + " high";
    elements.capturedAt.textContent = formatDate(snapshot.captured_at);
    elements.portfolioCount.textContent = snapshot.application_count + " recorded";
    renderApplicationList(snapshot.applications);
    renderSignals(snapshot);
    renderActivity(snapshot.recent_activity);
  }

  async function load() {
    setMode("loading");
    try {
      const response = await fetch("/dashboard/state", {
        headers: { Accept: "application/json" },
        credentials: "same-origin",
      });
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error("Sign in to view this workspace's recorded state.");
        }
        throw new Error("The backend did not return dashboard state (" + response.status + ").");
      }
      const snapshot = await response.json();
      if (snapshot.application_count === 0) {
        setMode("empty");
        return;
      }
      render(snapshot);
      setMode("content");
    } catch (error) {
      errorMessage.textContent = error instanceof Error ? error.message : "Try again shortly.";
      setMode("error");
    }
  }

  refreshButton.addEventListener("click", load);
  retryButton.addEventListener("click", load);
  load();
})();
