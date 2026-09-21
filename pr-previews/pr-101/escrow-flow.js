const ROUTES = [
    {
        id: 'complete',
        number: '01',
        tone: 'release',
        icon: 'fa-circle-check',
        trigger: 'Oracle confirms',
        title: 'Party B gets paid',
        summary: 'The agreed amount goes to Party B. Any meaningful extra returns to Party A.',
        tag: 'Normal completion',
        technicalTitle: 'Oracle-confirmed release',
        technicalSummary: 'The oracle attests the committed message. The payout destinations and minimum amounts were fixed when the escrow was created.',
        facts: [
            ['Who enables it', 'The oracle attests the event; the Arkade server and covenant emulator authorize the spend.'],
            ['Gate', 'The signed message must hash to oracleMessageHash.'],
            ['Party signatures', 'Neither party signs this path.'],
            ['Contract path', 'complete'],
        ],
        outputs: [
            {
                index: '0',
                recipient: 'Party B',
                constraint: 'At least amount',
                destination: 'Raw script parameter · partyBScript',
            },
            {
                index: '1',
                recipient: 'Party A',
                constraint: 'The full surplus, when greater than 330 sats',
                destination: 'Raw script parameter · partyAScript',
            },
        ],
    },
    {
        id: 'cancel',
        number: '02',
        tone: 'refund',
        icon: 'fa-clock-rotate-left',
        trigger: 'Deadline passes',
        title: 'Party A gets a full refund',
        summary: 'Every locked satoshi returns to Party A after the agreed deadline.',
        tag: 'Timeout protection',
        technicalTitle: 'Timeout refund',
        technicalSummary: 'Once the absolute timeout is reached, the covenant permits only a full-value refund to Party A.',
        facts: [
            ['Who enables it', 'The Arkade server and covenant emulator authorize the spend. Anyone may provide the transaction.'],
            ['Gate', 'Transaction time must be at least timeoutHeight.'],
            ['Witness', 'No contract witness is required.'],
            ['Contract path', 'cancel'],
        ],
        outputs: [
            {
                index: '0',
                recipient: 'Party A',
                constraint: 'At least the full escrow input',
                destination: 'Raw script parameter · partyAScript',
            },
        ],
    },
    {
        id: 'unilateral',
        number: '03',
        tone: 'recovery',
        icon: 'fa-people-arrows-left-right',
        trigger: 'Recovery delay passes',
        title: 'Both parties decide together',
        summary: 'Party A and Party B approve where the funds go. Neither can recover them alone.',
        tag: 'Joint recovery',
        technicalTitle: 'Two-party recovery',
        technicalSummary: 'This L1 recovery leaf becomes available after the relative delay and requires both party signatures.',
        facts: [
            ['Who enables it', 'Party A and Party B together.'],
            ['Gate', 'The input age must satisfy older(exit).'],
            ['Infrastructure', 'The Arkade server, emulator, and oracle are not required.'],
            ['Contract path', 'unilateral'],
        ],
        outputs: [
            {
                index: 'Any',
                recipient: 'Chosen together',
                constraint: 'Not constrained by the contract',
                destination: 'Unconstrained',
            },
        ],
    },
];

const REQUIRED_PARAMETERS = [
    'partyAPk',
    'partyBPk',
    'oraclePk',
    'oracleMessageHash',
    'partyAScript',
    'partyBScript',
    'amount',
    'timeoutHeight',
    'exit',
];

export function supportsEscrowFlow(artifact) {
    if (artifact?.contractName !== 'Escrow') return false;

    const parameters = new Set((artifact.constructorInputs || []).map(parameter => parameter.name));
    const groups = new Set((artifact.functions || []).map(group => group.name));
    return REQUIRED_PARAMETERS.every(name => parameters.has(name))
        && ROUTES.every(route => groups.has(route.id));
}

function routeCard(route) {
    return `
        <article class="escrow-route escrow-route-${route.tone}">
            <div class="escrow-route-number">${route.number}</div>
            <div class="escrow-route-icon" aria-hidden="true">
                <i class="fas ${route.icon}"></i>
            </div>
            <p class="escrow-route-trigger">${route.trigger}</p>
            <h3>${route.title}</h3>
            <p class="escrow-route-summary">${route.summary}</p>
            <div class="escrow-route-footer">
                <span>${route.tag}</span>
                <button type="button" class="escrow-detail-button" data-escrow-detail="${route.id}">
                    Technical details
                    <i class="fas fa-arrow-right" aria-hidden="true"></i>
                </button>
            </div>
        </article>`;
}

function outputCard(output) {
    return `
        <div class="escrow-technical-output">
            <span class="escrow-output-index">Output ${output.index}</span>
            <strong>${output.recipient}</strong>
            <span>${output.constraint}</span>
            <code>${output.destination}</code>
        </div>`;
}

export function escrowTechnicalDetailsMarkup(routeId) {
    const route = ROUTES.find(candidate => candidate.id === routeId);
    if (!route) return '';

    return `
        <div class="escrow-drawer-heading">
            <span class="escrow-drawer-route">${route.number} · ${route.tag}</span>
            <h2>${route.technicalTitle}</h2>
            <p>${route.technicalSummary}</p>
        </div>
        <dl class="escrow-facts">
            ${route.facts.map(([label, value]) => `
                <div>
                    <dt>${label}</dt>
                    <dd>${value}</dd>
                </div>`).join('')}
        </dl>
        <section class="escrow-output-details">
            <p class="escrow-section-label">Money destination</p>
            ${route.outputs.map(outputCard).join('')}
        </section>
        <button type="button" class="escrow-assembly-button" data-escrow-assembly="${route.id}">
            <i class="fas fa-microchip" aria-hidden="true"></i>
            View compiled assembly
        </button>`;
}

export function escrowFlowMarkup({ modified = false } = {}) {
    return `
        <section class="escrow-flow-shell">
            <div class="escrow-flow-glow escrow-flow-glow-one"></div>
            <div class="escrow-flow-glow escrow-flow-glow-two"></div>

            <header class="escrow-flow-header">
                <div>
                    <div class="escrow-flow-kicker">
                        <span></span>
                        Escrow at a glance
                    </div>
                    <h2>One deposit. Three safe outcomes.</h2>
                    <p>Party A locks the funds. The contract controls when—and how—they can move.</p>
                </div>
                <div class="escrow-flow-actions">
                    <span class="escrow-flow-status${modified ? ' escrow-flow-status-warning' : ''}">
                        <i class="fas ${modified ? 'fa-triangle-exclamation' : 'fa-circle-check'}" aria-hidden="true"></i>
                        ${modified ? 'Bespoke view—verify after edits' : 'Matches compiled Escrow'}
                    </span>
                    <button type="button" class="escrow-fullscreen-button" aria-label="Open flow full screen">
                        <i class="fas fa-expand" aria-hidden="true"></i>
                        <span>Present</span>
                    </button>
                </div>
            </header>

            <div class="escrow-actors" aria-label="Contract participants">
                <div class="escrow-actor">
                    <span class="escrow-avatar escrow-avatar-a">A</span>
                    <span><strong>Party A</strong><small>Locks the funds</small></span>
                </div>
                <div class="escrow-actor">
                    <span class="escrow-avatar escrow-avatar-oracle"><i class="fas fa-sparkles" aria-hidden="true"></i></span>
                    <span><strong>Oracle</strong><small>Confirms the event</small></span>
                </div>
                <div class="escrow-actor">
                    <span class="escrow-avatar escrow-avatar-b">B</span>
                    <span><strong>Party B</strong><small>Receives payment</small></span>
                </div>
            </div>

            <main class="escrow-flow-journey">
                <div class="escrow-vault">
                    <div class="escrow-vault-rings" aria-hidden="true">
                        <span></span><span></span><span></span>
                        <i class="fas fa-lock"></i>
                    </div>
                    <p>Funds locked</p>
                    <h3>Escrow</h3>
                    <span>Waiting for a valid outcome</span>
                </div>

                <svg class="escrow-flow-lines" viewBox="0 0 900 112" preserveAspectRatio="none" aria-hidden="true">
                    <defs>
                        <linearGradient id="escrow-release-line" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="0" stop-color="#8af0c8" stop-opacity=".75"/>
                            <stop offset="1" stop-color="#45c99a" stop-opacity=".2"/>
                        </linearGradient>
                        <linearGradient id="escrow-refund-line" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="0" stop-color="#8cc8ff" stop-opacity=".75"/>
                            <stop offset="1" stop-color="#4a9ae8" stop-opacity=".2"/>
                        </linearGradient>
                        <linearGradient id="escrow-recovery-line" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="0" stop-color="#d1aeff" stop-opacity=".75"/>
                            <stop offset="1" stop-color="#9d67e8" stop-opacity=".2"/>
                        </linearGradient>
                    </defs>
                    <path class="escrow-line escrow-line-release" d="M450,0 C450,58 150,45 150,112"/>
                    <path class="escrow-line escrow-line-refund" d="M450,0 L450,112"/>
                    <path class="escrow-line escrow-line-recovery" d="M450,0 C450,58 750,45 750,112"/>
                </svg>

                <div class="escrow-outcomes">
                    ${ROUTES.map(routeCard).join('')}
                </div>
            </main>

            <footer class="escrow-trust-note">
                <span class="escrow-trust-icon"><i class="fas fa-shield-halved" aria-hidden="true"></i></span>
                <span>
                    <strong>Protected by design</strong>
                    Normal payouts are fixed. The recovery path needs both parties.
                </span>
            </footer>

            <div class="escrow-drawer-backdrop" hidden></div>
            <aside class="escrow-detail-drawer" aria-hidden="true" aria-label="Escrow technical details" inert>
                <button type="button" class="escrow-drawer-close" aria-label="Close technical details">
                    <i class="fas fa-xmark" aria-hidden="true"></i>
                </button>
                <div class="escrow-drawer-content"></div>
            </aside>
        </section>`;
}

export function mountEscrowFlow(container, {
    modified = false,
    onViewAssembly = () => {},
} = {}) {
    if (container._escrowFlowCleanup) container._escrowFlowCleanup();
    container.innerHTML = escrowFlowMarkup({ modified });

    const shell = container.querySelector('.escrow-flow-shell');
    const drawer = shell.querySelector('.escrow-detail-drawer');
    const drawerContent = shell.querySelector('.escrow-drawer-content');
    const backdrop = shell.querySelector('.escrow-drawer-backdrop');
    const closeButton = shell.querySelector('.escrow-drawer-close');
    const fullscreenButton = shell.querySelector('.escrow-fullscreen-button');
    let returnFocus = null;

    const closeDetails = () => {
        shell.classList.remove('escrow-details-open');
        drawer.setAttribute('aria-hidden', 'true');
        drawer.inert = true;
        backdrop.hidden = true;
        returnFocus?.focus();
        returnFocus = null;
    };

    const openDetails = (routeId, trigger) => {
        drawerContent.innerHTML = escrowTechnicalDetailsMarkup(routeId);
        returnFocus = trigger;
        shell.classList.add('escrow-details-open');
        drawer.setAttribute('aria-hidden', 'false');
        drawer.inert = false;
        backdrop.hidden = false;
        closeButton.focus();

        drawerContent.querySelector('.escrow-assembly-button')?.addEventListener('click', () => {
            closeDetails();
            onViewAssembly(routeId);
        });
    };

    shell.querySelectorAll('[data-escrow-detail]').forEach(button => {
        button.addEventListener('click', () => openDetails(button.dataset.escrowDetail, button));
    });
    closeButton.addEventListener('click', closeDetails);
    backdrop.addEventListener('click', closeDetails);

    const onKeyDown = event => {
        if (event.key === 'Escape' && shell.classList.contains('escrow-details-open')) {
            closeDetails();
        }
    };
    shell.addEventListener('keydown', onKeyDown);

    const syncFullscreenButton = () => {
        const expanded = document.fullscreenElement === shell || shell.classList.contains('escrow-flow-expanded');
        fullscreenButton.querySelector('i').className = `fas ${expanded ? 'fa-compress' : 'fa-expand'}`;
        fullscreenButton.querySelector('span').textContent = expanded ? 'Exit' : 'Present';
        fullscreenButton.setAttribute('aria-label', expanded ? 'Exit full screen' : 'Open flow full screen');
    };

    const toggleFullscreen = async () => {
        try {
            if (document.fullscreenElement === shell) {
                await document.exitFullscreen();
            } else if (shell.requestFullscreen) {
                await shell.requestFullscreen();
            } else {
                shell.classList.toggle('escrow-flow-expanded');
                syncFullscreenButton();
            }
        } catch {
            shell.classList.toggle('escrow-flow-expanded');
            syncFullscreenButton();
        }
    };

    fullscreenButton.addEventListener('click', toggleFullscreen);
    document.addEventListener('fullscreenchange', syncFullscreenButton);

    container._escrowFlowCleanup = () => {
        document.removeEventListener('fullscreenchange', syncFullscreenButton);
    };
}

export function markEscrowFlowStale(container) {
    const status = container.querySelector('.escrow-flow-status');
    if (!status) return;
    status.classList.add('escrow-flow-status-warning');
    status.innerHTML = '<i class="fas fa-rotate" aria-hidden="true"></i> Source changed—compile to refresh';
}
