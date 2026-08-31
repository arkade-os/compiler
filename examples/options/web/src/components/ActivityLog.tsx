import { useStore } from "../state/store";
import { Card } from "../ui";

export function ActivityLog() {
  const { snapshot } = useStore();
  return (
    <Card title="Activity">
      <div className="ark-log">
        {snapshot.events.length === 0 && <span className="faint">No activity yet.</span>}
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
