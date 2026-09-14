const processes = [
  {name:"Manufacturing",system:"MES / OT",owner:"VP Manufacturing / Plant Operations",criticality:"Critical",impact:"Production disruption or shutdown, delayed customer orders, financial impact, and potential operational or safety consequences.",scores:["High","High","High","Medium","High","High"]},
  {name:"Finance",system:"ERP",owner:"Chief Financial Officer (CFO)",criticality:"Critical",impact:"Disruption to financial transactions, invoicing, payments, and reporting, potentially resulting in financial and compliance impacts.",scores:["High","High","Medium","High","Low","Medium"]},
  {name:"Supply Chain",system:"ERP",owner:"Chief Supply Chain Officer (CSCO)",criticality:"Critical",impact:"Disruption to supplier orders, inventory, procurement and logistics, potentially causing material shortages, production delays and customer delivery impacts.",scores:["High","High","High","Medium","Medium","High"]},
  {name:"Product Engineering",system:"PLM",owner:"VP Engineering / R&D",criticality:"High",impact:"Disruption to engineering and product development, with potential impact to intellectual property, project timelines and competitive position.",scores:["High","High","Medium","Medium","Low","High"]},
  {name:"Sales",system:"CRM",owner:"Chief Sales Officer (CSO)",criticality:"High",impact:"Disruption to customer management, quotations, sales operations and customer service, potentially resulting in revenue loss and customer dissatisfaction.",scores:["High","High","High","Medium","Low","High"]},
  {name:"Email & Collaboration",system:"Microsoft 365",owner:"Chief Information Officer (CIO)",criticality:"High",impact:"Loss of corporate communication and collaboration, reducing productivity and potentially disrupting business coordination.",scores:["Medium","High","Medium","Low","Low","Medium"]},
  {name:"IT Service Management",system:"ServiceNow",owner:"Chief Information Officer (CIO)",criticality:"High",impact:"Disruption to incident, request, change and problem management, potentially slowing recovery and increasing operational downtime.",scores:["Medium","High","Medium","Medium","Low","Medium"]},
  {name:"Human Resources",system:"HR System",owner:"Chief Human Resources Officer (CHRO)",criticality:"Medium",impact:"Disruption to payroll, employee services, recruitment and HR operations while core business operations can generally continue.",scores:["Medium","Medium","Low","Medium","Low","Low"]}
];

const jewels = [
  {name:"Manufacturing Execution System (MES)",type:"Application / OT",process:"Manufacturing",owner:"VP Manufacturing / Plant Operations",why:"Supports manufacturing operations and production execution.",cia:["High","High","High"],tags:["Triple High","OT"]},
  {name:"Product Lifecycle Management (PLM)",type:"Application / Information",process:"Product Engineering",owner:"VP Engineering / R&D",why:"Supports product development and critical product-lifecycle information.",cia:["High","High","Medium"],tags:[]},
  {name:"Enterprise Resource Planning (ERP)",type:"Application",process:"Finance / Supply Chain",owner:"CFO / Chief Supply Chain Officer",why:"Supports financial, procurement, inventory and supply-chain operations.",cia:["High","High","High"],tags:["Triple High"]},
  {name:"Customer Relationship Management (CRM)",type:"Application / Information",process:"Sales",owner:"Chief Sales Officer (CSO)",why:"Supports customer management, sales operations and customer information.",cia:["High","High","Medium"],tags:[]},
  {name:"Engineering Design Repository",type:"Information / Data",process:"Product Engineering",owner:"VP Engineering / R&D",why:"Contains engineering designs, technical documentation and intellectual property.",cia:["High","High","Medium"],tags:[]},
  {name:"Microsoft Entra ID",type:"Identity / Security Platform",process:"Enterprise-wide",owner:"CIO",why:"Controls identities and access to applications, cloud resources and corporate services.",cia:["High","High","High"],tags:["Triple High","Enterprise-wide"]},
  {name:"Manufacturing OT / ICS Environment",type:"OT Infrastructure",process:"Manufacturing",owner:"VP Manufacturing / Plant Operations",why:"Supports industrial control and production; disruption may create safety consequences.",cia:["Medium","High","High"],tags:["OT"]},
  {name:"Customer & Business Data",type:"Information / Data",process:"Enterprise-wide",owner:"Relevant Business Function Owner",why:"Sensitive information requiring protection against disclosure, modification or loss.",cia:["High","High","Medium"],tags:["Enterprise-wide"]}
];

const impactLabels = ["Financial","Operational","Customer","Legal / regulatory","Safety","Reputation"];
let activeFilter = "All";
let activeProcess = processes[0];

function badge(level){return `<span class="criticality-badge ${level.toLowerCase()}">${level}</span>`}

function renderProcesses(){
  const query = document.querySelector("#process-search").value.trim().toLowerCase();
  const filtered = processes.filter(process => (activeFilter === "All" || process.criticality === activeFilter) && `${process.name} ${process.system} ${process.owner}`.toLowerCase().includes(query));
  const body = document.querySelector("#process-table");
  body.innerHTML = filtered.map(process => `<tr tabindex="0" data-process="${process.name}" class="${process.name === activeProcess.name ? "selected" : ""}" aria-label="View ${process.name} details"><td><strong>${process.name}</strong></td><td>${process.system}</td><td>${process.owner}</td><td>${badge(process.criticality)}</td></tr>`).join("");
  document.querySelector("#empty-state").hidden = filtered.length !== 0;
  body.querySelectorAll("tr").forEach(row => {
    const select = () => {activeProcess = processes.find(process => process.name === row.dataset.process); renderProcesses(); renderDetail();};
    row.addEventListener("click", select);
    row.addEventListener("keydown", event => {if(event.key === "Enter" || event.key === " "){event.preventDefault();select();}});
  });
}

function renderDetail(){
  document.querySelector("#process-detail").innerHTML = `<span class="detail-label">Selected business process</span><h3>${activeProcess.name}</h3><div class="detail-meta"><div><span>System dependency</span><strong>${activeProcess.system}</strong></div><div><span>Business priority</span><strong>${activeProcess.criticality}</strong></div></div><span class="detail-label">Accountable owner</span><p><strong>${activeProcess.owner}</strong></p><span class="detail-label">Potential business impact</span><p>${activeProcess.impact}</p>`;
}

function renderImpact(){
  const cells = ["Business process",...impactLabels].map(label => `<div class="impact-cell header">${label}</div>`);
  processes.forEach(process => {
    cells.push(`<div class="impact-cell process">${process.name}</div>`);
    process.scores.forEach(score => cells.push(`<div class="impact-cell value ${score.toLowerCase()}"><span>${score}</span></div>`));
  });
  document.querySelector("#impact-grid").innerHTML = cells.join("");
}

function renderJewels(filter="All"){
  const selected = filter === "All" ? jewels : jewels.filter(jewel => jewel.tags.includes(filter));
  document.querySelector("#jewel-grid").innerHTML = selected.map(jewel => `<article class="jewel-card"><span class="asset-type">${jewel.type}</span><h3>${jewel.name}</h3><p>${jewel.why}</p><div class="cia-row" aria-label="CIA assessment"><div class="${jewel.cia[0].toLowerCase()}"><span>Conf.</span><strong>${jewel.cia[0]}</strong></div><div class="${jewel.cia[1].toLowerCase()}"><span>Integrity</span><strong>${jewel.cia[1]}</strong></div><div class="${jewel.cia[2].toLowerCase()}"><span>Avail.</span><strong>${jewel.cia[2]}</strong></div></div></article>`).join("");
}

document.querySelectorAll(".filter").forEach(button => button.addEventListener("click", () => {
  activeFilter = button.dataset.filter;
  document.querySelectorAll(".filter").forEach(item => {item.classList.toggle("active",item===button);item.setAttribute("aria-pressed",String(item===button));});
  renderProcesses();
}));
document.querySelector("#process-search").addEventListener("input",renderProcesses);
document.querySelectorAll(".jewel-filter").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".jewel-filter").forEach(item => {item.classList.toggle("active",item===button);item.setAttribute("aria-pressed",String(item===button));});
  renderJewels(button.dataset.jewelFilter);
}));

renderProcesses();
renderDetail();
renderImpact();
renderJewels();
