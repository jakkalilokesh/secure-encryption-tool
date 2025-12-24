import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

export default function Toast({ message, type = "info", onClose }) {
    useEffect(() => {
        const timer = setTimeout(() => {
            onClose();
        }, 4000);
        return () => clearTimeout(timer);
    }, [onClose]);

    const bgColors = {
        info: "bg-blue-600 border-blue-400",
        success: "bg-green-600 border-green-400",
        error: "bg-red-600 border-red-400",
        warning: "bg-yellow-600 border-yellow-400"
    };

    const icons = {
        info: "ℹ️",
        success: "✅",
        error: "⚠️",
        warning: "🚧"
    };

    return (
        <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-6 py-4 rounded-lg shadow-2xl border ${bgColors[type]} text-white min-w-[300px] backdrop-blur-md bg-opacity-90`}
        >
            <span className="text-xl">{icons[type]}</span>
            <div className="flex-1">
                <p className="font-semibold">{type === 'error' ? 'Error' : type === 'success' ? 'Success' : 'Notification'}</p>
                <p className="text-sm opacity-90">{message}</p>
            </div>
            <button onClick={onClose} className="opacity-50 hover:opacity-100 ml-2">✕</button>
        </motion.div>
    );
}
