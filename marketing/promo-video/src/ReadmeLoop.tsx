import "./index.css";
import {
  AbsoluteFill,
  Easing,
  Sequence,
  interpolate,
  useCurrentFrame,
} from "remotion";

/* ------------------------------------------------------------------ */
/*  Timing                                                             */
/* ------------------------------------------------------------------ */

const fps = 30;
const sec = (value: number) => Math.round(value * fps);

const SCENE = sec(6); // frames per step (slow, readable pacing)
export const readmeLoopDurationInFrames = SCENE * 3; // three steps

/* ------------------------------------------------------------------ */
/*  Brand palette (Automic Vault — "hardened mission console")         */
/* ------------------------------------------------------------------ */

const bg = "#0a0d10"; // nuclear black
const panel = "#12191d"; // flat terminal body
const bar = "#0a0d10"; // title bar
const ink = "#d6c7a1"; // fallout beige
const inkMuted = "#b89b73"; // muted beige
const red = "#d83a2f"; // iron red — danger / exposed
const amber = "#ffb347"; // radar amber — prompt / caution
const green = "#6bffb0"; // terminal green — safe / locked
const appGreen = "#1adb94"; // app green — secured action
const line = "rgba(214, 199, 161, 0.34)";
const lineFaint = "rgba(214, 199, 161, 0.16)";

const display =
  '"Barlow Condensed", "Arial Narrow", Impact, ui-sans-serif, system-ui, sans-serif';
const mono =
  '"Geist Mono", "SFMono-Regular", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

/* ------------------------------------------------------------------ */
/*  Geometry (1200 x 680 banner)                                       */
/* ------------------------------------------------------------------ */

const PAD = 56;
const CARD = { x: PAD, y: 230, w: 1200 - PAD * 2, h: 388 };
const BAR_H = 44;
const BODY = {
  x: CARD.x,
  y: CARD.y + BAR_H,
  w: CARD.w,
  h: CARD.h - BAR_H,
  padX: 36,
  padY: 26,
  lineH: 38,
};

/* ------------------------------------------------------------------ */
/*  Animation helpers (matches the other compositions)                 */
/* ------------------------------------------------------------------ */

const clamp = {
  extrapolateLeft: "clamp" as const,
  extrapolateRight: "clamp" as const,
};
const easeOut = Easing.bezier(0.16, 1, 0.3, 1);

const fade = (frame: number, start: number, end: number) =>
  interpolate(frame, [start, end], [0, 1], { ...clamp, easing: easeOut });

const fadeOut = (frame: number, start: number, end: number) =>
  interpolate(frame, [start, end], [1, 0], {
    ...clamp,
    easing: Easing.bezier(0.7, 0, 0.84, 0),
  });

const rise = (frame: number, start: number, end: number, from: number) =>
  interpolate(frame, [start, end], [from, 0], { ...clamp, easing: easeOut });

const typeText = (
  text: string,
  frame: number,
  start: number,
  duration: number,
) => {
  if (frame < start) {
    return "";
  }
  const progress = Math.min(1, (frame - start + 1) / duration);
  return text.slice(0, Math.ceil(text.length * progress));
};

// Steady-period cursor so the loop seam never lands mid-blink.
const cursorOn = (frame: number) => Math.floor((frame % 16) / 8) % 2 === 0;

/* ------------------------------------------------------------------ */
/*  Persistent chrome — never fades, keeps the loop seam invisible     */
/* ------------------------------------------------------------------ */

const Grid: React.FC = () => (
  <AbsoluteFill
    style={{
      backgroundImage: `linear-gradient(${lineFaint} 1px, transparent 1px), linear-gradient(90deg, ${lineFaint} 1px, transparent 1px)`,
      backgroundSize: "48px 48px",
      opacity: 0.5,
    }}
  />
);

const CardChrome: React.FC = () => (
  <>
    {/* terminal card */}
    <div
      style={{
        position: "absolute",
        left: CARD.x,
        top: CARD.y,
        width: CARD.w,
        height: CARD.h,
        borderRadius: 12,
        background: panel,
        border: `1px solid ${line}`,
      }}
    />
    {/* title bar */}
    <div
      style={{
        position: "absolute",
        left: CARD.x,
        top: CARD.y,
        width: CARD.w,
        height: BAR_H,
        borderTopLeftRadius: 12,
        borderTopRightRadius: 12,
        background: bar,
        borderBottom: `1px solid ${lineFaint}`,
        display: "flex",
        alignItems: "center",
        gap: 18,
        paddingLeft: 22,
        paddingRight: 22,
      }}
    >
      <div style={{ display: "flex", gap: 9 }}>
        {[red, amber, green].map((c) => (
          <span
            key={c}
            style={{ width: 11, height: 11, borderRadius: 999, background: c }}
          />
        ))}
      </div>
      <span
        style={{
          fontFamily: mono,
          fontWeight: 700,
          fontSize: 15,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: ink,
        }}
      >
        automic vault
      </span>
      <span style={{ flex: 1 }} />
      <span
        style={{
          fontFamily: mono,
          fontWeight: 600,
          fontSize: 13,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: amber,
          border: `1px solid rgba(255, 179, 71, 0.45)`,
          borderRadius: 5,
          padding: "3px 9px",
        }}
      >
        local
      </span>
    </div>
    {/* footer tagline */}
    <span
      style={{
        position: "absolute",
        left: PAD,
        top: 642,
        fontFamily: mono,
        fontSize: 15,
        letterSpacing: "0.04em",
        color: inkMuted,
      }}
    >
      no magic. just fewer ambient privileges.
    </span>
  </>
);

/* ------------------------------------------------------------------ */
/*  Header + body building blocks                                      */
/* ------------------------------------------------------------------ */

const Header: React.FC<{ eyebrow: string; title: string; op: number; y: number }> = ({
  eyebrow,
  title,
  op,
  y,
}) => (
  <div
    style={{
      position: "absolute",
      left: PAD,
      top: 52,
      width: 1200 - PAD * 2,
      opacity: op,
      transform: `translateY(${y}px)`,
    }}
  >
    <div
      style={{
        fontFamily: mono,
        fontWeight: 700,
        fontSize: 18,
        letterSpacing: "0.26em",
        textTransform: "uppercase",
        color: amber,
        marginBottom: 14,
      }}
    >
      {eyebrow}
    </div>
    <div
      style={{
        fontFamily: display,
        fontWeight: 800,
        fontSize: 60,
        lineHeight: 0.96,
        letterSpacing: "-0.01em",
        color: ink,
        whiteSpace: "pre-line",
      }}
    >
      {title}
    </div>
  </div>
);

const Body: React.FC<{ op: number; children: React.ReactNode }> = ({
  op,
  children,
}) => (
  <div
    style={{
      position: "absolute",
      left: BODY.x,
      top: BODY.y,
      width: BODY.w,
      height: BODY.h,
      padding: `${BODY.padY}px ${BODY.padX}px`,
      opacity: op,
      display: "flex",
      flexDirection: "column",
      justifyContent: "flex-start",
      gap: 6,
      fontFamily: mono,
      fontSize: 25,
    }}
  >
    {children}
  </div>
);

const Prompt: React.FC<{ cmd: string; frame: number; typeAt: number; dur: number }> = ({
  cmd,
  frame,
  typeAt,
  dur,
}) => {
  const typed = typeText(cmd, frame, typeAt, dur);
  const done = typed.length >= cmd.length;
  const showCursor = !done && frame >= typeAt && cursorOn(frame);
  return (
    <div
      style={{
        fontFamily: mono,
        fontWeight: 700,
        fontSize: 25,
        lineHeight: `${BODY.lineH}px`,
        color: ink,
        whiteSpace: "pre",
      }}
    >
      <span style={{ color: amber }}>{"$ "}</span>
      {typed}
      <span style={{ opacity: showCursor ? 1 : 0, color: ink }}>{"█"}</span>
    </div>
  );
};

const Row: React.FC<{
  frame: number;
  at: number;
  children: React.ReactNode;
  style?: React.CSSProperties;
}> = ({ frame, at, children, style }) => (
  <div
    style={{
      opacity: fade(frame, at, at + 9),
      transform: `translateY(${rise(frame, at, at + 9, 8)}px)`,
      lineHeight: `${BODY.lineH}px`,
      display: "flex",
      alignItems: "baseline",
      ...style,
    }}
  >
    {children}
  </div>
);

const Badge: React.FC<{ text: string; color: string }> = ({ text, color }) => (
  <span
    style={{
      marginLeft: "auto",
      fontFamily: mono,
      fontWeight: 700,
      fontSize: 15,
      letterSpacing: "0.12em",
      color,
      border: `1px solid ${color}`,
      borderRadius: 5,
      padding: "2px 9px",
      alignSelf: "center",
    }}
  >
    {text}
  </span>
);

/* ------------------------------------------------------------------ */
/*  Step 1 — SCAN                                                      */
/* ------------------------------------------------------------------ */

const FindingRow: React.FC<{
  frame: number;
  at: number;
  path: string;
  detail: string;
  badge: string;
  badgeColor: string;
  textColor: string;
}> = ({ frame, at, path, detail, badge, badgeColor, textColor }) => (
  <Row frame={frame} at={at}>
    <span style={{ color: textColor, width: 230, flexShrink: 0 }}>{path}</span>
    <span style={{ color: inkMuted }}>{detail}</span>
    <Badge text={badge} color={badgeColor} />
  </Row>
);

const ScanStep: React.FC<{ frame: number; op: number; hy: number }> = ({
  frame,
  op,
  hy,
}) => (
  <>
    <Header
      eyebrow="01 · scan"
      title="Find plaintext secrets."
      op={op}
      y={hy}
    />
    <Body op={op}>
      <Prompt cmd="av scan" frame={frame} typeAt={8} dur={18} />
      <div style={{ height: 8 }} />
      <FindingRow
        frame={frame}
        at={44}
        path="~/.netrc"
        detail="login password"
        badge="HIGH"
        badgeColor={red}
        textColor={ink}
      />
      <FindingRow
        frame={frame}
        at={64}
        path=".env"
        detail="STRIPE_SECRET_KEY"
        badge="HIGH"
        badgeColor={red}
        textColor={ink}
      />
      <Row frame={frame} at={86} style={{ marginTop: 8 }}>
        <span style={{ color: red, marginRight: 10 }}>{"✕"}</span>
        <span style={{ color: inkMuted }}>
          2 findings · plaintext credentials visible to agents
        </span>
      </Row>
    </Body>
  </>
);

/* ------------------------------------------------------------------ */
/*  Step 2 — HARDEN                                                    */
/* ------------------------------------------------------------------ */

const HardenStep: React.FC<{ frame: number; op: number; hy: number }> = ({
  frame,
  op,
  hy,
}) => {
  // One "secured" sweep passes across the output once.
  const sweepX = interpolate(frame, [92, 116], [-160, BODY.w], clamp);
  const sweepVisible = frame >= 92 && frame <= 116;
  return (
    <>
      <Header
        eyebrow="02 · harden"
        title="Store it in the vault."
        op={op}
        y={hy}
      />
      <Body op={op}>
        <Prompt cmd="av save STRIPE_SECRET_KEY" frame={frame} typeAt={8} dur={34} />
        <div style={{ height: 8 }} />
        <div style={{ position: "relative" }}>
          {sweepVisible && (
            <div
              style={{
                position: "absolute",
                top: -4,
                left: sweepX,
                width: 150,
                height: BODY.lineH * 2 + 12,
                background:
                  "linear-gradient(90deg, transparent, rgba(26, 219, 148, 0.18), transparent)",
                pointerEvents: "none",
              }}
            />
          )}
          <Row frame={frame} at={58}>
            <span style={{ color: appGreen, marginRight: 10 }}>{"✓"}</span>
            <span style={{ color: inkMuted }}>
              stored in the Automic Vault keychain
            </span>
          </Row>
          <Row frame={frame} at={80}>
            <span style={{ color: appGreen, marginRight: 10 }}>{"✓"}</span>
            <span style={{ color: inkMuted }}>
              kept out of .env, shell history, and model context
            </span>
          </Row>
        </div>
      </Body>
    </>
  );
};

/* ------------------------------------------------------------------ */
/*  Step 3 — GATE                                                      */
/* ------------------------------------------------------------------ */

const GateButton: React.FC<{ label: string; color: string; selected: boolean }> = ({
  label,
  color,
  selected,
}) => (
  <span
    style={{
      fontFamily: mono,
      fontWeight: 700,
      fontSize: 21,
      letterSpacing: "0.08em",
      color,
      border: `1px solid ${selected ? color : "rgba(214, 199, 161, 0.28)"}`,
      background: selected ? `${color}1f` : "transparent",
      borderRadius: 6,
      padding: "6px 18px",
    }}
  >
    {label}
  </span>
);

const GateStep: React.FC<{ frame: number; op: number; hy: number }> = ({
  frame,
  op,
  hy,
}) => {
  // Selection settles on Deny for a risky publish.
  const denySelected = frame >= 106;
  return (
    <>
      <Header
        eyebrow="03 · gate"
        title="Gate risky commands."
        op={op}
        y={hy}
      />
      <Body op={op}>
        <Prompt cmd="av contain codex" frame={frame} typeAt={8} dur={24} />
        <div style={{ height: 8 }} />
        <Row frame={frame} at={48}>
          <span style={{ color: amber, marginRight: 10 }}>{"■"}</span>
          <span style={{ color: ink }}>codex wants to run</span>
        </Row>
        <Row frame={frame} at={66} style={{ marginTop: 2, marginBottom: 6 }}>
          <span
            style={{
              color: ink,
              fontWeight: 700,
              marginLeft: 28,
              padding: "4px 14px",
              border: `1px solid ${line}`,
              borderRadius: 6,
              background: "rgba(216, 58, 47, 0.08)",
            }}
          >
            npm publish
          </span>
        </Row>
        <Row frame={frame} at={88} style={{ gap: 16, marginLeft: 28, marginTop: 4 }}>
          <GateButton label="Approve" color={appGreen} selected={false} />
          <GateButton label="Deny" color={red} selected={denySelected} />
        </Row>
        <Row frame={frame} at={124} style={{ marginTop: 8 }}>
          <span style={{ color: red, marginRight: 10 }}>{"✕"}</span>
          <span style={{ color: inkMuted }}>blocked — npm publish did not run</span>
        </Row>
      </Body>
    </>
  );
};

/* ------------------------------------------------------------------ */
/*  Per-step wrapper: fade content in/out so chrome carries the loop   */
/* ------------------------------------------------------------------ */

const Step: React.FC<{ index: 0 | 1 | 2 }> = ({ index }) => {
  const frame = useCurrentFrame();
  const op = fade(frame, 0, 18) * fadeOut(frame, SCENE - 20, SCENE - 5);
  const hy = rise(frame, 0, 20, 16);
  if (index === 0) return <ScanStep frame={frame} op={op} hy={hy} />;
  if (index === 1) return <HardenStep frame={frame} op={op} hy={hy} />;
  return <GateStep frame={frame} op={op} hy={hy} />;
};

export const ReadmeLoopComposition: React.FC = () => {
  return (
    <AbsoluteFill style={{ background: bg }}>
      <Grid />
      <CardChrome />
      <Sequence durationInFrames={SCENE}>
        <Step index={0} />
      </Sequence>
      <Sequence from={SCENE} durationInFrames={SCENE}>
        <Step index={1} />
      </Sequence>
      <Sequence from={SCENE * 2} durationInFrames={SCENE}>
        <Step index={2} />
      </Sequence>
    </AbsoluteFill>
  );
};
