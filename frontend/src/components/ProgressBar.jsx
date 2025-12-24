import React from "react";

export default function ProgressBar({ progress = 0, label }) {
  const getColorClass = (progress) => {
    if (progress < 30) return "bg-red-500";
    if (progress < 60) return "bg-yellow-500";
    if (progress < 90) return "bg-blue-500";
    return "bg-cyberGreen";
  };

  return (
    <div className="mt-6 w-full">
      {/* Container with inner shadow */}
      <div className="w-full bg-cyberGray border border-cyberGreen rounded-sm p-[2px] shadow-neonGreen relative overflow-hidden">

        {/* Fill */}
        <div
          className={`h-3 ${getColorClass(progress)} transition-all duration-500 ease-out relative z-10 rounded-sm`}
          style={{ width: `${progress}%` }}
        ></div>
      </div>

      {/* Label and Percentage */}
      <div className="flex justify-between items-center mt-2">
        <p className="text-cyberGreen text-sm">
          {label || "Progress"}
        </p>
        <p className="text-cyberGreen text-sm font-mono">
          {progress}%
        </p>
      </div>
    </div>
  );
}