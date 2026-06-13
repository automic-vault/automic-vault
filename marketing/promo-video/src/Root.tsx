import "./index.css";
import { Composition } from "remotion";
import {
  BrewInstallSecurityComposition,
  brewInstallSecurityDurationInFrames,
} from "./BrewInstallSecurity";
import { MyComposition, durationInFrames } from "./Composition";
import {
  DontGetOwnedComposition,
  dontGetOwnedDurationInFrames,
} from "./DontGetOwned";
import {
  ReadmeLoopComposition,
  readmeLoopDurationInFrames,
} from "./ReadmeLoop";
import {
  ScannerOneLinerComposition,
  scannerOneLinerDurationInFrames,
} from "./ScannerOneLiner";
import { SecretSkillsComposition, secretSkillsDurationInFrames } from "./SecretSkills";

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="AutomicVaultPromo"
        component={MyComposition}
        durationInFrames={durationInFrames}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="AutomicVaultSkillSecrets"
        component={SecretSkillsComposition}
        durationInFrames={secretSkillsDurationInFrames}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="AutomicVaultBrewInstallSecurity"
        component={BrewInstallSecurityComposition}
        durationInFrames={brewInstallSecurityDurationInFrames}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="AutomicVaultScannerOneLiner"
        component={ScannerOneLinerComposition}
        durationInFrames={scannerOneLinerDurationInFrames}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="AutomicVaultDontGetOwned"
        component={DontGetOwnedComposition}
        durationInFrames={dontGetOwnedDurationInFrames}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="AutomicVaultReadmeLoop"
        component={ReadmeLoopComposition}
        durationInFrames={readmeLoopDurationInFrames}
        fps={30}
        width={1200}
        height={680}
      />
    </>
  );
};
