import React, { useState } from "react";
import FileDropZone from "../components/FileDropZone";
import NeonButton from "../components/NeonButton";
import { hideDataInImage, revealDataFromImage } from "../api";
import { motion } from "framer-motion";

export default function StegPage() {
    const [activeTab, setActiveTab] = useState("hide");

    const [coverImage, setCoverImage] = useState(null);
    const [secretFile, setSecretFile] = useState(null);
    const [isHiding, setIsHiding] = useState(false);

    const [stegImage, setStegImage] = useState(null);
    const [isRevealing, setIsRevealing] = useState(false);

    const [status, setStatus] = useState("");
    const [error, setError] = useState("");

    const handleHide = async () => {
        if (!coverImage || !secretFile) {
            setError("Please select both a cover image and a secret file.");
            return;
        }

        setIsHiding(true);
        setError("");
        setStatus("Processing... This happens on the server.");

        try {
            const blob = await hideDataInImage(coverImage, secretFile);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "secret_image.png";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setStatus("Success! secret_image.png downloaded.");
        } catch (err) {
            setError(err.message);
            setStatus("");
        } finally {
            setIsHiding(false);
        }
    };

    const handleReveal = async () => {
        if (!stegImage) {
            setError("Please upload an image containing hidden data.");
            return;
        }

        setIsRevealing(true);
        setError("");
        setStatus("Extracting data...");

        try {
            const blob = await revealDataFromImage(stegImage);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "eave_drop_content.bin";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setStatus("Success! Hidden data extracted.");
        } catch (err) {
            setError(err.message);
            setStatus("");
        } finally {
            setIsRevealing(false);
        }
    };

    return (
        <div className="text-white max-w-4xl mx-auto">
            <h1 className="text-4xl text-cyberGreen font-bold mb-2">Steganography</h1>
            <p className="text-gray-400 mb-8">Hide secret files inside innocent-looking images.</p>

            <div className="flex border-b border-gray-700 mb-8">
                <button
                    className={`px-6 py-3 font-bold transition-colors ${activeTab === 'hide' ? 'text-cyberGreen border-b-2 border-cyberGreen' : 'text-gray-500 hover:text-white'}`}
                    onClick={() => { setActiveTab('hide'); setError(""); setStatus(""); }}
                >
                    Hide Data
                </button>
                <button
                    className={`px-6 py-3 font-bold transition-colors ${activeTab === 'reveal' ? 'text-cyberGreen border-b-2 border-cyberGreen' : 'text-gray-500 hover:text-white'}`}
                    onClick={() => { setActiveTab('reveal'); setError(""); setStatus(""); }}
                >
                    Reveal Data
                </button>
            </div>

            {error && (
                <div className="mb-6 p-4 bg-red-900/30 border border-red-500 rounded text-red-300">
                    ⚠️ {error}
                </div>
            )}

            {status && (
                <div className="mb-6 p-4 bg-blue-900/30 border border-blue-500 rounded text-blue-300">
                    ℹ️ {status}
                </div>
            )}

            {activeTab === 'hide' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <h3 className="text-xl font-bold mb-4 text-gray-300">1. Select Cover Image (PNG)</h3>
                            <FileDropZone
                                onFilesSelected={(files) => setCoverImage(files[0])}
                                multiple={false}
                                accept="image/png"
                            />
                            {coverImage && <p className="mt-2 text-cyberGreen text-sm">Selected: {coverImage.name}</p>}
                        </div>
                        <div>
                            <h3 className="text-xl font-bold mb-4 text-gray-300">2. Select Secret File</h3>
                            <FileDropZone
                                onFilesSelected={(files) => setSecretFile(files[0])}
                                multiple={false}
                            />
                            {secretFile && <p className="mt-2 text-cyberGreen text-sm">Selected: {secretFile.name}</p>}
                        </div>
                    </div>

                    <div className="mt-8 text-center">
                        <NeonButton onClick={handleHide} disabled={isHiding}>
                            {isHiding ? "Encoding..." : "Hide Data & Download Image"}
                        </NeonButton>
                    </div>
                </motion.div>
            )}

            {activeTab === 'reveal' && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                    <h3 className="text-xl font-bold mb-4 text-gray-300">Select Image with Hidden Data</h3>
                    <FileDropZone
                        onFilesSelected={(files) => setStegImage(files[0])}
                        multiple={false}
                        accept="image/png"
                    />
                    {stegImage && <p className="mt-2 text-cyberGreen text-sm">Selected: {stegImage.name}</p>}

                    <div className="mt-8 text-center">
                        <NeonButton onClick={handleReveal} disabled={isRevealing}>
                            {isRevealing ? "Extracting..." : "Reveal Hidden Data"}
                        </NeonButton>
                    </div>
                </motion.div>
            )}

        </div>
    );
}
