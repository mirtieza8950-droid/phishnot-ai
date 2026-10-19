import { Warp } from "@paper-design/shaders-react";
import { useNavigate } from "react-router-dom";
import { Mail, Link2, Mic, Smartphone, Camera, MessageSquare,
         ShieldCheck, Search, KeyRound, Monitor, Layers, BarChart2 } from "lucide-react";

const DEFAULT_FEATURES = [
  {
    title: "Suspicious Email?",
    description:
      "Paste any message. Our AI flags phishing attempts, social engineering, and deceptive links — then explains exactly what it found.",
    route: "/scan/email",
    icon: <Mail className="w-10 h-10 text-white" />,
  },
  {
    title: "Unfamiliar Link?",
    description:
      "Don't click blind. Paste any URL and we'll reveal where it leads, score it across 70+ security engines, and trace every redirect.",
    route: "/scan/url",
    icon: <Link2 className="w-10 h-10 text-white" />,
  },
  {
    title: "Suspicious Phone Call?",
    description:
      "Upload a recording. We transcribe it and identify IRS scams, fake tech support, bank fraud, gift-card demands, and arrest threats.",
    route: "/vishing",
    icon: <Mic className="w-10 h-10 text-white" />,
  },
  {
    title: "Strange Text Message?",
    description:
      "Paste the SMS. We catch delivery scams, fake bank alerts, OTP theft attempts, and short-link traps used in smishing campaigns.",
    route: "/mobile",
    icon: <Smartphone className="w-10 h-10 text-white" />,
  },
  {
    title: "Got a Screenshot?",
    description:
      "Can't copy the text? Upload an image — our vision AI reads and analyzes whatever's inside it, including embedded URLs and QR codes.",
    route: "/scan/image",
    icon: <Camera className="w-10 h-10 text-white" />,
  },
  {
    title: "Not Sure? Ask the AI.",
    description:
      "Describe what you received and our security analyst AI will tell you what it is, how it works, and what you should do next.",
    route: "/chat",
    icon: <MessageSquare className="w-10 h-10 text-white" />,
  },
];

const getShaderConfig = (index) => {
  const configs = [
    {
      proportion: 0.3,
      softness: 0.8,
      distortion: 0.15,
      swirl: 0.6,
      swirlIterations: 8,
      shape: "checks",
      shapeScale: 0.08,
      // Purple — Email
      colors: ["hsl(247, 100%, 20%)", "hsl(247, 100%, 50%)", "hsl(260, 90%, 35%)", "hsl(250, 100%, 65%)"],
    },
    {
      proportion: 0.4,
      softness: 1.2,
      distortion: 0.2,
      swirl: 0.9,
      swirlIterations: 12,
      shape: "dots",
      shapeScale: 0.12,
      // Cyan — URL
      colors: ["hsl(190, 100%, 20%)", "hsl(190, 100%, 55%)", "hsl(200, 90%, 30%)", "hsl(185, 100%, 65%)"],
    },
    {
      proportion: 0.35,
      softness: 0.9,
      distortion: 0.18,
      swirl: 0.7,
      swirlIterations: 10,
      shape: "checks",
      shapeScale: 0.1,
      // Red — Vishing
      colors: ["hsl(348, 100%, 20%)", "hsl(348, 100%, 55%)", "hsl(340, 90%, 30%)", "hsl(350, 100%, 65%)"],
    },
    {
      proportion: 0.45,
      softness: 1.1,
      distortion: 0.22,
      swirl: 0.8,
      swirlIterations: 15,
      shape: "dots",
      shapeScale: 0.09,
      // Orange — Mobile
      colors: ["hsl(38, 100%, 25%)", "hsl(38, 100%, 55%)", "hsl(30, 90%, 35%)", "hsl(42, 100%, 65%)"],
    },
    {
      proportion: 0.38,
      softness: 0.95,
      distortion: 0.16,
      swirl: 0.85,
      swirlIterations: 11,
      shape: "checks",
      shapeScale: 0.11,
      // Green — Screenshot
      colors: ["hsl(142, 100%, 18%)", "hsl(142, 70%, 45%)", "hsl(130, 80%, 28%)", "hsl(145, 65%, 55%)"],
    },
    {
      proportion: 0.42,
      softness: 1.0,
      distortion: 0.19,
      swirl: 0.75,
      swirlIterations: 9,
      shape: "dots",
      shapeScale: 0.13,
      // Pink — AI Chat
      colors: ["hsl(328, 100%, 22%)", "hsl(328, 100%, 55%)", "hsl(318, 90%, 35%)", "hsl(332, 100%, 65%)"],
    },
  ];
  return configs[index % configs.length];
};

export const ADVANCED_FEATURES = [
  {
    title: "Brand Protection",
    description: "Monitor the web for lookalike domains, typosquatting, and sites impersonating your brand before they reach your customers.",
    route: "/brand",
    icon: <ShieldCheck className="w-10 h-10 text-white" />,
  },
  {
    title: "Kit Fingerprinting",
    description: "Identify which phishing kit was used to build a malicious page. Match known signatures and track campaign infrastructure.",
    route: "/kit",
    icon: <Search className="w-10 h-10 text-white" />,
  },
  {
    title: "OAuth Detector",
    description: "Catch fake login pages, token theft flows, and consent phishing attacks targeting OAuth app permissions.",
    route: "/oauth",
    icon: <KeyRound className="w-10 h-10 text-white" />,
  },
  {
    title: "Browser Sandbox",
    description: "Execute suspicious URLs in an isolated browser environment and observe behavior without any risk to your system.",
    route: "/sandbox",
    icon: <Monitor className="w-10 h-10 text-white" />,
  },
  {
    title: "Batch Scanner",
    description: "Upload a list of emails or URLs and scan hundreds of items at once. Ideal for incident response and bulk triage.",
    route: "/batch",
    icon: <Layers className="w-10 h-10 text-white" />,
  },
  {
    title: "Analytics",
    description: "Visualize threat trends, scan volumes, and detection rates over time. Track what's targeting you and when.",
    route: "/analytics",
    icon: <BarChart2 className="w-10 h-10 text-white" />,
  },
];

export default function FeaturesCards({ features = DEFAULT_FEATURES }) {
  const navigate = useNavigate();

  return (
    <section className="py-16 px-4">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => {
            const shaderConfig = getShaderConfig(index);
            return (
              <div
                key={index}
                className="relative h-72 cursor-pointer group"
                onClick={() => navigate(feature.route)}>
                <div className="absolute inset-0 rounded-2xl overflow-hidden">
                  <Warp
                    style={{ height: "100%", width: "100%" }}
                    proportion={shaderConfig.proportion}
                    softness={shaderConfig.softness}
                    distortion={shaderConfig.distortion}
                    swirl={shaderConfig.swirl}
                    swirlIterations={shaderConfig.swirlIterations}
                    shape={shaderConfig.shape}
                    shapeScale={shaderConfig.shapeScale}
                    scale={1}
                    rotation={0}
                    speed={0.7}
                    colors={shaderConfig.colors}
                  />
                </div>
                <div className="relative z-10 p-6 rounded-2xl h-full flex flex-col bg-black/50 border border-white/10 group-hover:bg-black/40 transition-colors">
                  <div className="mb-4 filter drop-shadow-lg">{feature.icon}</div>
                  <h3 className="text-lg font-bold mb-3 text-white">{feature.title}</h3>
                  <p className="text-sm leading-relaxed flex-grow text-gray-200 font-medium">
                    {feature.description}
                  </p>
                  <div className="mt-4 flex items-center text-xs font-bold text-gray-300 group-hover:text-white transition-colors">
                    <span className="mr-1.5">Scan now</span>
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
