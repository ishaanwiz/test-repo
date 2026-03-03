import { exec } from 'child_process';

export function executeVulnerableSystemCommand(userInput) {
  exec('echo ' + userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`Execution error: ${error.message}`);
      return;
    }
    console.log(`Output: ${stdout}`);
    if (stderr) {
      console.error(`Error Output: ${stderr}`);
    }
  });
}