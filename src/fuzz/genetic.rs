//! Genetic Algorithm Engine - Payload evolution based on response differentials
//!
//! Implements a genetic algorithm that evolves payloads across generations,
//! selecting for successful mutations based on response analysis feedback.

use crate::payload::{GeneratedPayload, PayloadClass, Severity, SafetyLevel};
use crate::fuzz::mutator::{PayloadMutator, MutatorConfig, MutationType};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Fitness score for a payload based on response analysis
#[derive(Debug, Clone, Copy, Default)]
pub struct FitnessScore {
    /// Response delta magnitude (0.0 to 1.0)
    pub response_delta: f64,
    /// Timing anomaly detected
    pub timing_anomaly: f64,
    /// Status code indicates potential success
    pub status_score: f64,
    /// Reflection detected in response
    pub reflection_score: f64,
    /// Error message patterns found
    pub error_pattern_score: f64,
}

impl FitnessScore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate overall fitness (weighted sum)
    pub fn calculate(&self) -> f64 {
        self.response_delta * 0.3
            + self.timing_anomaly * 0.2
            + self.status_score * 0.15
            + self.reflection_score * 0.25
            + self.error_pattern_score * 0.1
    }

    /// Create from response analysis results
    pub fn from_response(
        response_delta: f64,
        timing_ms: f64,
        status_code: u16,
        reflection_detected: bool,
        error_patterns: usize,
    ) -> Self {
        let timing_anomaly = if timing_ms > 1000.0 { 1.0 } else { timing_ms / 1000.0 };
        
        let status_score = match status_code {
            200 => 0.3,
            500..=599 => 0.8,
            400..=499 => 0.5,
            _ => 0.1,
        };

        Self {
            response_delta,
            timing_anomaly,
            status_score,
            reflection_score: if reflection_detected { 1.0 } else { 0.0 },
            error_pattern_score: (error_patterns as f64).min(1.0),
        }
    }
}

/// Individual in the genetic population
#[derive(Debug, Clone)]
pub struct Individual {
    pub payload: GeneratedPayload,
    pub fitness: FitnessScore,
    pub generation: u32,
    pub parent_ids: Vec<String>,
}

impl Individual {
    pub fn new(payload: GeneratedPayload, generation: u32) -> Self {
        Self {
            payload,
            fitness: FitnessScore::new(),
            generation,
            parent_ids: Vec::new(),
        }
    }

    pub fn with_fitness(mut self, fitness: FitnessScore) -> Self {
        self.fitness = fitness;
        self
    }

    pub fn with_parents(mut self, parent_ids: Vec<String>) -> Self {
        self.parent_ids = parent_ids;
        self
    }
}

/// Configuration for the genetic algorithm
#[derive(Debug, Clone)]
pub struct GeneticConfig {
    /// Population size per generation
    pub population_size: usize,
    /// Number of elite individuals to preserve
    pub elite_count: usize,
    /// Tournament selection size
    pub tournament_size: usize,
    /// Crossover probability
    pub crossover_rate: f64,
    /// Mutation probability
    pub mutation_rate: f64,
    /// Maximum generations
    pub max_generations: u32,
    /// Fitness threshold for early termination
    pub fitness_threshold: f64,
    /// Stagnation limit (generations without improvement)
    pub stagnation_limit: u32,
}

impl Default for GeneticConfig {
    fn default() -> Self {
        Self {
            population_size: 50,
            elite_count: 5,
            tournament_size: 5,
            crossover_rate: 0.7,
            mutation_rate: 0.3,
            max_generations: 100,
            fitness_threshold: 0.9,
            stagnation_limit: 10,
        }
    }
}

/// Genetic algorithm engine for payload evolution
pub struct GeneticEngine {
    config: GeneticConfig,
    mutator: PayloadMutator,
    population: Vec<Individual>,
    best_fitness: f64,
    generation: u32,
    history: HashMap<String, FitnessScore>,
}

impl GeneticEngine {
    /// Create a new genetic engine with configuration
    pub fn new(config: GeneticConfig) -> Self {
        let mutator = PayloadMutator::new(MutatorConfig::default());
        
        Self {
            config,
            mutator,
            population: Vec::new(),
            best_fitness: 0.0,
            generation: 0,
            history: HashMap::new(),
        }
    }

    /// Initialize population with seed payloads
    pub fn initialize(&mut self, seed_payloads: Vec<GeneratedPayload>) {
        self.population = seed_payloads
            .into_iter()
            .map(|p| Individual::new(p, 0))
            .collect();
        
        // Ensure minimum population size
        while self.population.len() < self.config.population_size {
            if let Some(individual) = self.population.first() {
                let mutated = self.mutator.mutate(&individual.payload);
                for m in mutated {
                    self.population.push(Individual::new(m, 0));
                    if self.population.len() >= self.config.population_size {
                        break;
                    }
                }
            }
        }
    }

    /// Run one generation of evolution
    pub fn evolve(&mut self) -> Vec<Individual> {
        self.generation += 1;
        
        // Sort by fitness (descending)
        self.population.sort_by(|a, b| {
            b.fitness.calculate().partial_cmp(&a.fitness.calculate()).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Track best fitness
        if let Some(best) = self.population.first() {
            let fitness = best.fitness.calculate();
            if fitness > self.best_fitness {
                self.best_fitness = fitness;
            }
        }

        // Elitism - preserve top individuals
        let elites: Vec<Individual> = self.population[..self.config.elite_count.min(self.population.len())]
            .iter()
            .cloned()
            .collect();

        // Create new population through selection, crossover, and mutation
        let mut new_population = elites.clone();

        while new_population.len() < self.config.population_size {
            // Tournament selection
            let parent1 = self.tournament_select();
            let parent2 = self.tournament_select();

            // Crossover
            let offspring = if rand::random::<f64>() < self.config.crossover_rate {
                self.crossover(&parent1, &parent2)
            } else {
                vec![parent1.clone(), parent2.clone()]
            };

            // Mutation
            for mut child in offspring {
                if rand::random::<f64>() < self.config.mutation_rate {
                    let mutated = self.mutator.mutate(&child.payload);
                    if let Some(m) = mutated.into_iter().next() {
                        child.payload = m;
                    }
                }
                child.generation = self.generation;
                new_population.push(child);
            }
        }

        self.population = new_population;
        elites
    }

    /// Update fitness scores based on response analysis
    pub fn update_fitness(&mut self, payload_id: &str, score: FitnessScore) {
        self.history.insert(payload_id.to_string(), score);
        
        for individual in &mut self.population {
            if individual.payload.id == payload_id {
                individual.fitness = score;
                break;
            }
        }
    }

    /// Get the best performing payloads
    pub fn get_best(&self, count: usize) -> Vec<&Individual> {
        let mut sorted: Vec<&Individual> = self.population.iter().collect();
        sorted.sort_by(|a, b| {
            b.fitness.calculate().partial_cmp(&a.fitness.calculate()).unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.into_iter().take(count).collect()
    }

    /// Check if evolution should terminate
    pub fn should_terminate(&self) -> bool {
        self.generation >= self.config.max_generations
            || self.best_fitness >= self.config.fitness_threshold
    }

    /// Get current generation number
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Get best fitness achieved
    pub fn best_fitness(&self) -> f64 {
        self.best_fitness
    }

    /// Get population size
    pub fn population_size(&self) -> usize {
        self.population.len()
    }

    /// Get all payloads from current population
    pub fn get_all_payloads(&self) -> Vec<GeneratedPayload> {
        self.population.iter().map(|i| i.payload.clone()).collect()
    }

    /// Reset the engine for a new scan target
    pub fn reset(&mut self) {
        self.population.clear();
        self.best_fitness = 0.0;
        self.generation = 0;
    }

    fn tournament_select(&self) -> Individual {
        let mut rng = rand::rngs::StdRng::seed_from_u64(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
        );
        
        let mut best: Option<&Individual> = None;
        for _ in 0..self.config.tournament_size {
            let idx = rng.gen_range(0..self.population.len());
            let individual = &self.population[idx];
            
            if best.is_none() || individual.fitness.calculate() > best.unwrap().fitness.calculate() {
                best = Some(individual);
            }
        }
        
        best.cloned().unwrap_or_else(|| self.population[0].clone())
    }

    fn crossover(&self, parent1: &Individual, parent2: &Individual) -> Vec<Individual> {
        let p1 = &parent1.payload.raw;
        let p2 = &parent2.payload.raw;
        
        if p1.is_empty() || p2.is_empty() {
            return vec![parent1.clone(), parent2.clone()];
        }

        // Single-point crossover
        let point1 = rand::random::<usize>() % (p1.len() + 1);
        let point2 = rand::random::<usize>() % (p2.len() + 1);

        let (p1_left, p1_right) = p1.split_at(point1.min(p1.len()));
        let (p2_left, p2_right) = p2.split_at(point2.min(p2.len()));

        let child1_raw = format!("{}{}", p1_left, p2_right);
        let child2_raw = format!("{}{}", p2_left, p1_right);

        vec![
            Individual::new(
                GeneratedPayload::new(
                    format!("{}-cross-{}", parent1.payload.id, self.generation),
                    child1_raw,
                    parent1.payload.class.clone(),
                    parent1.payload.severity,
                    parent1.payload.safety,
                ),
                self.generation,
            ).with_parents(vec![parent1.payload.id.clone(), parent2.payload.id.clone()]),
            Individual::new(
                GeneratedPayload::new(
                    format!("{}-cross-{}", parent2.payload.id, self.generation),
                    child2_raw,
                    parent2.payload.class.clone(),
                    parent2.payload.severity,
                    parent2.payload.safety,
                ),
                self.generation,
            ).with_parents(vec![parent1.payload.id.clone(), parent2.payload.id.clone()]),
        ]
    }
}

/// Thread-safe wrapper for concurrent genetic evolution
#[derive(Clone)]
pub struct SharedGeneticEngine {
    inner: Arc<RwLock<GeneticEngine>>,
}

impl SharedGeneticEngine {
    pub fn new(engine: GeneticEngine) -> Self {
        Self {
            inner: Arc::new(RwLock::new(engine)),
        }
    }

    pub async fn evolve(&self) -> Vec<Individual> {
        let mut engine = self.inner.write().await;
        engine.evolve()
    }

    pub async fn update_fitness(&self, payload_id: &str, score: FitnessScore) {
        let mut engine = self.inner.write().await;
        engine.update_fitness(payload_id, score);
    }

    pub async fn get_best(&self, count: usize) -> Vec<Individual> {
        let engine = self.inner.read().await;
        engine.get_best(count).into_iter().cloned().collect()
    }

    pub async fn get_payloads(&self) -> Vec<GeneratedPayload> {
        let engine = self.inner.read().await;
        engine.get_all_payloads()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fitness_calculation() {
        let score = FitnessScore::from_response(0.8, 1500.0, 500, true, 2);
        let fitness = score.calculate();
        assert!(fitness > 0.5);
    }

    #[test]
    fn test_genetic_engine_initialization() {
        let config = GeneticConfig::default();
        let mut engine = GeneticEngine::new(config);
        
        let seed = vec![
            GeneratedPayload::new("seed-1", "' OR 1=1", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("seed-2", "<script>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
        ];
        
        engine.initialize(seed);
        assert!(engine.population_size() >= 2);
    }

    #[test]
    fn test_evolution_step() {
        let config = GeneticConfig {
            population_size: 10,
            elite_count: 2,
            ..Default::default()
        };
        let mut engine = GeneticEngine::new(config);
        
        let seed = vec![
            GeneratedPayload::new("seed-1", "test payload", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
        ];
        
        engine.initialize(seed);
        let elites = engine.evolve();
        
        assert_eq!(engine.generation(), 1);
        assert!(!elites.is_empty());
    }

    #[test]
    fn test_fitness_update() {
        let mut engine = GeneticEngine::new(GeneticConfig::default());
        
        let payload = GeneratedPayload::new("test", "payload", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe);
        engine.initialize(vec![payload.clone()]);
        
        let score = FitnessScore::from_response(0.9, 2000.0, 500, true, 3);
        engine.update_fitness("test", score);
        
        let best = engine.get_best(1);
        assert!(!best.is_empty());
    }
}
