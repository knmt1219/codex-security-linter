import React from 'react';

export function UserContent({ payload }) {
    // Insecure DOM injection
    return <div dangerouslySetInnerHTML={{ __html: payload }} />;
}
