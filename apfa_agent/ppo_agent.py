from stable_baselines3 import PPO
from apfa_agent.environment import PentestingEnv
import yaml
from pathlib import Path
import os

class PPOAgent:
    def __init__(self, state_manager, tool_manager, llm_client, executor, config_path: str = "apfa_agent/config/agent_config.yaml"):
        self.state_manager = state_manager
        self.tool_manager = tool_manager
        self.llm_client = llm_client
        self.executor = executor
        self.config_path = config_path
        self.model = None
        self.env = None
        
        # Load config
        self.config = self._load_config()
        self.model_path = Path(self.config.get('model_path', 'data/agent_results/ppo_model'))
        
        # Create environment
        self.env = PentestingEnv(
            state_manager=self.state_manager,
            tool_manager=self.tool_manager,
            llm_client=self.llm_client,
            executor=self.executor,
            max_steps=self.config.get('max_steps', 50),
            skill_persistence=self.config.get('skill_persistence', 'persist_with_decay')
        )

    def _load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        return {}

    def set_environment(self, env):
        """Set the environment for the agent"""
        self.env = env
        # If model exists, we might need to re-attach env?
        if self.model:
            self.model.set_env(env)

    def load(self):
        """Load the model from disk"""
        if self.model_path.with_suffix('.zip').exists():
            self.model = PPO.load(self.model_path, env=self.env, device='cpu')
            print(f"Model loaded from {self.model_path}")
        else:
            print("No saved model found, initializing new one")
            self.initialize_model()

    def initialize_model(self, force_new: bool = False):
        """Initialize PPO with expanded action space"""
        # Check if model file exists (with .zip extension which SB3 adds)
        model_file = self.model_path.with_suffix('.zip') if self.model_path.suffix != '.zip' else self.model_path
        
        if not force_new and model_file.exists():
            print(f"Loading existing model from {model_file}")
            self.model = PPO.load(model_file, env=self.env, device='cpu')
        else:
            print("Initializing new PPO model")
            self.model = PPO(
                "MlpPolicy",
                self.env,
                learning_rate=self.config.get('learning_rate', 0.0003),
                n_steps=self.config.get('n_steps', 2048),
                batch_size=self.config.get('batch_size', 64),
                n_epochs=self.config.get('n_epochs', 10),
                gamma=self.config.get('gamma', 0.99),
                ent_coef=self.config.get('ent_coef', 0.01), # Added entropy coefficient
                verbose=1,
                tensorboard_log=self.config.get('tensorboard_log', "data/agent_results/tensorboard/"),
                device='cpu'
            )

    def train(self, total_timesteps: int = 10000):
        if self.model is None:
            self.initialize_model()
        
        print(f"Training PPO agent for {total_timesteps} timesteps...")
        self.model.learn(total_timesteps=total_timesteps)
        self.save_model()
        print("Training complete.")

    def predict(self, obs, deterministic: bool = True):
        if self.model is None:
            self.initialize_model()
        return self.model.predict(obs, deterministic=deterministic)

    def save_model(self):
        if self.model:
            # Ensure directory exists
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            self.model.save(self.model_path)
            print(f"Model saved to {self.model_path}")
    
    def evaluate(self, n_episodes: int = 10):
        """Evaluate the agent's performance"""
        if self.model is None:
            self.initialize_model()
            
        print(f"Evaluating agent for {n_episodes} episodes...")
        
        total_rewards = []
        success_count = 0
        
        for i in range(n_episodes):
            obs, _ = self.env.reset()
            done = False
            episode_reward = 0
            info = {}
            
            while not done:
                action, _ = self.model.predict(obs, deterministic=True)
                obs, reward, terminated, truncated, info = self.env.step(action)
                done = terminated or truncated
                episode_reward += reward
                
                if info.get('root_obtained'):
                    success_count += 1
            
            total_rewards.append(episode_reward)
            print(f"Episode {i+1}: Reward = {episode_reward:.2f}, Success = {info.get('root_obtained', False)}")
            
        avg_reward = sum(total_rewards) / len(total_rewards)
        success_rate = success_count / n_episodes
        
        print("\nEvaluation Results:")
        print(f"Average Reward: {avg_reward:.2f}")
        print(f"Success Rate: {success_rate:.1%}")
        
        return {
            'average_reward': avg_reward,
            'success_rate': success_rate,
            'episodes': n_episodes
        }
