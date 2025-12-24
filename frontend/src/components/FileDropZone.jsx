import React, { useRef, useState } from "react";

export default function FileDropZone({ onFilesSelected, multiple = true, accept }) {
  const inputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleManualSelect = (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) {
      onFilesSelected(files);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files || []);
    if (files.length > 0) {
      onFilesSelected(files);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  return (
    <div
      onClick={() => inputRef.current && inputRef.current.click()}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      className={`
        w-full h-32 flex flex-col justify-center items-center
        border ${isDragging ? 'border-cyberBlue' : 'border-cyberGreen'}
        rounded-md cursor-pointer
        ${isDragging ? 'shadow-neonBlue' : 'hover:shadow-neonGreen'}
        transition-all duration-300 p-6 text-center
        ${isDragging ? 'bg-cyberBlue/10' : 'hover:bg-gray-900/30'}
      `}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        multiple={multiple}
        onChange={handleManualSelect}
        accept={accept}
      />

      <div className="text-cyberGreen text-xl mb-2">
        {isDragging ? "Drop files here" : "Click or drop files here"}
      </div>

      <div className="text-gray-400 text-sm">
        {multiple ? "Multiple files supported" : "Single file only"}
      </div>

      {!isDragging && (
        <div className="mt-3 text-xs text-gray-500">
          Max: 10GB per file • All file types supported
        </div>
      )}
    </div>
  );
}