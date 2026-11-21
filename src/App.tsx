/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect } from 'react';
import { mountGuardianApp } from './guardian/05_interface_and_rendering';

export default function App() {
  useEffect(() => {
    return mountGuardianApp();
  }, []);

  return <div className="w" id="app" />;
}
