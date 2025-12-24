import React from "react";
import { motion } from "framer-motion";

export default function InitialLoader() {
    return (
        <div className="fixed inset-0 bg-gray-900 z-[9999] flex flex-col items-center justify-center text-cyberGreen font-mono">
            <motion.div
                className="w-24 h-24 border-4 border-cyberGreen/30 border-t-cyberGreen rounded-full mb-8"
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            />

            <motion.h1
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
                className="text-2xl font-bold tracking-widest mb-2"
            >
                INITIALIZING SYSTEM
            </motion.h1>

            <motion.div
                initial={{ width: 0 }}
                animate={{ width: "200px" }}
                transition={{ duration: 2, ease: "easeInOut" }}
                className="h-1 bg-cyberBlue/50 overflow-hidden relative"
            >
                <motion.div
                    className="absolute top-0 bottom-0 left-0 bg-cyberBlue"
                    animate={{ left: ["-100%", "100%"] }}
                    transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                    style={{ width: "50%" }}
                />
            </motion.div>

            <div className="mt-4 text-xs text-cyberGreen/60">
                Establishing Secure Connection...
            </div>
        </div>
    );
}
