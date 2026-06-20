import { useStore } from "../state/store";
import { Badge, Card } from "../ui";

export function ActivityLog() {
  const { snapshot } = useStore();
  return (
    <Card title="Activity">
      <div className="ark-log">
        {snapshot.events.length === 0 && (
          <span className="faint">No activity yet.</span>
        )}
        {snapshot.events.map((e, i) => (
          <div key={i} className={`line ${e.level}`}>
            <span className="h">#{e.height.toLocaleString()}</span>
            <span className="t">{e.message}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function MempoolCard() {
  const { snapshot } = useStore();
  const recent = snapshot.txs.slice(0, 8);
  return (
    <Card title="Transactions">
      {recent.length === 0 && <span className="faint">No transactions yet.</span>}
      <div className="col" style={{ gap: 8 }}>
        {recent.map((t) => (
          <div key={t.id} className="row between center">
            <div className="row center" style={{ gap: 8 }}>
              <Badge tone={t.chain === "virtual" ? "lime" : "cyan"}>
                {t.chain === "virtual" ? "⚡" : "⛓"} {t.kind}
              </Badge>
              <span className="mono faint" style={{ fontSize: 11 }}>{t.id}</span>
            </div>
            <Badge tone={t.status === "confirmed" ? "green" : "amber"} dot={t.status === "pending"}>
              {t.status === "confirmed"
                ? "confirmed"
                : `pending → #${t.confirmAt?.toLocaleString()}`}
            </Badge>
          </div>
        ))}
      </div>
    </Card>
  );
}
