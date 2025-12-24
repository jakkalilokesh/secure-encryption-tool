import React from "react";

export default function ChunkSizeSelector({ chunkSize, setChunkSize, totalSize }) {
  const presets = [
    { label: "64 KB", value: 64 * 1024, desc: "Fast for small files" },
    { label: "256 KB", value: 256 * 1024, desc: "Balanced performance" },
    { label: "1 MB", value: 1024 * 1024, desc: "Recommended" },
    { label: "4 MB", value: 4 * 1024 * 1024, desc: "Large files" },
    { label: "10 MB", value: 10 * 1024 * 1024, desc: "Very large files" },
  ];

  const estimatedChunks = Math.ceil(totalSize / chunkSize);
  const estimatedMemory = Math.min(chunkSize * 2, 100 * 1024 * 1024); // Max 100MB estimate

  const formatBytes = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  return (
    <div className="border border-cyberGreen p-4 rounded-md bg-gray-900/30">
      <label className="text-cyberGreen block mb-2 font-semibold">
        Chunk Size Configuration
      </label>

      <p className="text-gray-400 text-sm mb-4">
        Larger chunks = fewer operations but more memory. Smaller chunks = better parallelism.
      </p>

      {/* Preset Buttons */}
      <div className="flex flex-wrap gap-2 mb-4">
        {presets.map((preset) => (
          <button
            key={preset.value}
            onClick={() => setChunkSize(preset.value)}
            className={`px-3 py-2 text-sm rounded border ${chunkSize === preset.value
                ? 'border-cyberGreen bg-cyberGreen/20 text-cyberGreen'
                : 'border-gray-600 text-gray-300 hover:border-gray-500'
              }`}
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Custom Slider */}
      <div className="mb-4">
        <div className="flex justify-between text-sm mb-1">
          <span className="text-gray-400">Custom Size</span>
          <span className="text-cyberGreen">{formatBytes(chunkSize)}</span>
        </div>

        <input
          type="range"
          min="65536" // 64KB
          max="10485760" // 10MB
          step="65536" // 64KB increments
          value={chunkSize}
          onChange={(e) => setChunkSize(parseInt(e.target.value))}
          className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
        />

        <div className="flex justify-between text-xs text-gray-500 mt-1">
          <span>64 KB</span>
          <span>10 MB</span>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 gap-4 p-3 bg-gray-800/50 rounded">
        <div>
          <div className="text-gray-400 text-sm">Estimated Chunks</div>
          <div className="text-lg">{estimatedChunks.toLocaleString()}</div>
        </div>
        <div>
          <div className="text-gray-400 text-sm">Memory Usage</div>
          <div className="text-lg">{formatBytes(estimatedMemory)}</div>
        </div>
        <div>
          <div className="text-gray-400 text-sm">Parallelism</div>
          <div className="text-lg">
            {chunkSize <= 256 * 1024 ? 'High' :
              chunkSize <= 1024 * 1024 ? 'Medium' : 'Low'}
          </div>
        </div>
        <div>
          <div className="text-gray-400 text-sm">Performance</div>
          <div className="text-lg">
            {chunkSize <= 256 * 1024 ? 'Fast (CPU)' :
              chunkSize <= 4 * 1024 * 1024 ? 'Balanced' : 'Fast (I/O)'}
          </div>
        </div>
      </div>

      <div className="mt-3 text-sm text-gray-400">
        {chunkSize <= 256 * 1024 && "Best for many small files. High parallelism."}
        {chunkSize > 256 * 1024 && chunkSize <= 1024 * 1024 && "Good balance for mixed file sizes."}
        {chunkSize > 1024 * 1024 && "Best for large individual files. Lower memory overhead."}
      </div>
    </div>
  );
}