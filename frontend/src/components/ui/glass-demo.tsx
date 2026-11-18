import GlassWorkspace, { warmPalette } from "@/components/ui/adjustable-glass-dashboard";

export default function GlassWorkspaceDemo() {
  return (
    <GlassWorkspace
      brand="Sentinel-XAI"
      userName="SOC Lead"
      periodLabel="November 2026"
      style={warmPalette}
      glass={{
        blur: 22,
        opacity: 0.3,
        saturation: 1.2,
        edge: 0.6,
        tint: "#eadbc7",
      }}
      backgroundImage="https://cdn.21st.dev/assets/mirror/4a/4a0ed73b8ab76bd427aa70ab124329127f3df27cc7f31223a832ed7d28b3dda4.jpg"
    />
  );
}
